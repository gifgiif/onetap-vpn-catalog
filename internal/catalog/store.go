package catalog

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Store interface{ Current() SignedCatalog }

type MemoryStore struct {
	mu           sync.RWMutex
	privateKey   *ecdsa.PrivateKey
	current      SignedCatalog
	revisionFile string
}

func NewMemoryStore(privateKey *ecdsa.PrivateKey) *MemoryStore {
	return &MemoryStore{privateKey: privateKey}
}

// NewPersistentMemoryStore retains the last signed catalog as well as its
// revision. It lets phones fetch a known-good catalog immediately after an API
// restart, while the importer is still checking a new upstream snapshot.
func NewPersistentMemoryStore(privateKey *ecdsa.PrivateKey, revisionFile string) (*MemoryStore, error) {
	store := NewMemoryStore(privateKey)
	store.revisionFile = revisionFile
	saved, complete, err := readSnapshot(revisionFile, privateKey)
	if os.IsNotExist(err) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	if complete {
		store.current = saved
		return store, nil
	}
	// A previous pilot build stored only a revision. Preserve monotonicity when
	// it upgrades; the first verified import creates the complete snapshot.
	store.current.Payload.Revision = saved.Payload.Revision
	return store, nil
}

func (s *MemoryStore) ReplaceFromLines(source string, lines []string) error {
	servers := make([]VLESS, 0, len(lines))
	for _, line := range lines {
		server, err := ParseVLESS(line, source)
		if err == nil {
			servers = append(servers, server)
		}
	}
	return s.Replace(source, servers)
}

// Replace atomically signs a ranked set of already restricted and validated
// candidates. Equivalent upstream URIs are collapsed to one effective Xray
// configuration, retaining the lower measured latency.
func (s *MemoryStore) Replace(source string, candidates []VLESS) error {
	if len(candidates) == 0 {
		return fmt.Errorf("empty replacement must not erase the fallback catalog")
	}
	unique := map[string]VLESS{}
	for _, candidate := range candidates {
		candidate.Source = source
		key := candidateKey(candidate)
		previous, exists := unique[key]
		if !exists || faster(candidate, previous) {
			unique[key] = candidate
		}
	}
	servers := make([]VLESS, 0, len(unique))
	for _, server := range unique {
		servers = append(servers, server)
	}
	sort.Slice(servers, func(i, j int) bool {
		if faster(servers[i], servers[j]) != faster(servers[j], servers[i]) {
			return faster(servers[i], servers[j])
		}
		return servers[i].ID < servers[j].ID
	})
	// Leave room in the 96-probe CI budget for discovering new routes next run.
	if len(servers) > 64 {
		chosen := make(map[string]bool)
		countries := make(map[string]bool)
		var pool []VLESS
		for _, server := range servers {
			if !countries[server.CountryCode] && len(pool) < 64 {
				pool = append(pool, server)
				chosen[server.ID] = true
				countries[server.CountryCode] = true
			}
		}
		for _, server := range servers {
			if !chosen[server.ID] && len(pool) < 64 {
				pool = append(pool, server)
			}
		}
		servers = pool
		sort.Slice(servers, func(i, j int) bool {
			if faster(servers[i], servers[j]) != faster(servers[j], servers[i]) {
				return faster(servers[i], servers[j])
			}
			return servers[i].ID < servers[j].ID
		})
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Every member of this set passed a fresh probe. Keep even a small set:
	// a country-count heuristic must never retain known failing routes for hours.
	revision := s.current.Payload.Revision + 1
	payload := Catalog{SchemaVersion: SchemaVersion, Revision: revision, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(6 * time.Hour), Servers: servers}
	bytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	signature, err := SignPayload(s.privateKey, bytes)
	if err != nil {
		return err
	}
	signed := SignedCatalog{Payload: payload, Signature: base64.StdEncoding.EncodeToString(signature), KeyID: KeyID}
	if s.revisionFile != "" {
		if err := persistSnapshot(s.revisionFile, signed); err != nil {
			return err
		}
	}
	s.current = signed
	return nil
}

func persistSnapshot(path string, signed SignedCatalog) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(signed)
	if err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

// readSnapshot accepts the legacy revision-only file for a one-time upgrade.
// complete is false for that format, so callers never serve it as a catalog.
func readSnapshot(path string, privateKey *ecdsa.PrivateKey) (saved SignedCatalog, complete bool, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return SignedCatalog{}, false, err
	}
	if err := json.Unmarshal(data, &saved); err == nil && saved.Signature != "" {
		payload, marshalErr := json.Marshal(saved.Payload)
		if marshalErr != nil || !VerifyPayloadSignature(&privateKey.PublicKey, payload, decodeSignature(saved.Signature)) {
			return SignedCatalog{}, false, &persistenceError{"saved catalog signature is invalid"}
		}
		if saved.Payload.SchemaVersion != SchemaVersion || saved.Payload.Revision == 0 || len(saved.Payload.Servers) == 0 {
			return SignedCatalog{}, false, &persistenceError{"saved catalog is incomplete"}
		}
		return saved, true, nil
	}
	revision, parseErr := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if parseErr != nil {
		return SignedCatalog{}, false, parseErr
	}
	return SignedCatalog{Payload: Catalog{Revision: revision}}, false, nil
}

func decodeSignature(value string) []byte {
	decoded, _ := base64.StdEncoding.DecodeString(value)
	return decoded
}

type persistenceError struct{ message string }

func (e *persistenceError) Error() string { return e.message }

func candidateKey(server VLESS) string {
	return strings.Join([]string{server.Host, strconv.Itoa(server.Port), server.UUID, server.Security, server.SNI, server.PublicKey, server.ShortID, server.Flow, server.Type}, "\x00")
}

func faster(left, right VLESS) bool {
	leftQuality, rightQuality := qualityBand(left), qualityBand(right)
	if leftQuality != rightQuality {
		return leftQuality < rightQuality
	}
	leftLatency, rightLatency := latencyRank(left.LatencyMs), latencyRank(right.LatencyMs)
	if leftLatency != rightLatency {
		return leftLatency < rightLatency
	}
	return left.ThroughputKbps > right.ThroughputKbps
}

// A single 256 KiB transfer is noisy. It must never promote a multi-second
// route above a usable low-latency one. Throughput breaks ties after latency.
func qualityBand(server VLESS) int {
	if server.LatencyMs <= 0 {
		return 2
	}
	if server.LatencyMs > 1500 || server.ThroughputKbps < 1500 {
		return 1
	}
	return 0
}

func latencyRank(latencyMs int) int {
	if latencyMs <= 0 {
		return int(^uint(0) >> 1)
	}
	return latencyMs
}

func (s *MemoryStore) Current() SignedCatalog {
	// API and checker run as separate containers in production. The checker
	// atomically replaces this file; reading it on demand avoids a stale API
	// process and never exposes a partially written catalog.
	if s.revisionFile != "" {
		if saved, complete, err := readSnapshot(s.revisionFile, s.privateKey); err == nil && complete {
			s.mu.Lock()
			if saved.Payload.Revision > s.current.Payload.Revision {
				s.current = saved
			}
			s.mu.Unlock()
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

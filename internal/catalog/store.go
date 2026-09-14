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

const (
	maxCatalogServers   = 64
	maxRoutesPerCountry = 4
	minimumUsefulRoutes = 12
)

// nearbyTargetCountries is a retention preference for people connecting from
// Russia and neighbouring networks. It does not claim that a route will work
// for every carrier; the device still makes the final local choice.
var nearbyTargetCountries = []string{
	"DE", "FI", "EE", "PL", "LV", "LT", "SE", "NL",
	"CZ", "DK", "NO", "AT", "CH", "FR", "BE", "GB",
	"RO", "SK", "HU", "SI", "HR", "BG", "IT", "ES",
	"PT", "GR", "IE", "KZ", "UZ", "AM", "TR",
}

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
	// A single public feed can dominate the measurements from a GitHub runner.
	// Keep several independently verified routes per country, but retain nearby
	// European exits before farther reserves. Applying this even below 64 rows
	// prevents a 64-row US-heavy pool from slipping through unchanged.
	servers = diverseCountryPool(servers, maxCatalogServers, maxRoutesPerCountry)
	sort.Slice(servers, func(i, j int) bool {
		if faster(servers[i], servers[j]) != faster(servers[j], servers[i]) {
			return faster(servers[i], servers[j])
		}
		return servers[i].ID < servers[j].ID
	})
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

// diverseCountryPool takes already quality-sorted candidates and selects in
// rounds: one route from every preferred nearby country, then one from every
// remaining country, then their second route, and so on. No country can crowd
// out the alternatives merely because a remote checker observed it as fast.
//
// A non-empty verified candidate set always produces at least one result. If a
// rare refresh finds fewer than minimumUsefulRoutes after the diversity cap,
// it fills only to that modest backup floor from other freshly verified routes.
// This avoids replacing a live pool with four same-country routes while never
// reviving stale historic nodes or allowing a large one-country catalog.
func diverseCountryPool(servers []VLESS, limit, maxPerCountry int) []VLESS {
	if len(servers) == 0 || limit <= 0 || maxPerCountry <= 0 {
		return nil
	}
	byCountry := make(map[string][]VLESS)
	encountered := make([]string, 0)
	seenCountries := make(map[string]bool)
	for _, server := range servers {
		country := countryBucket(server)
		if !seenCountries[country] {
			encountered = append(encountered, country)
			seenCountries[country] = true
		}
		byCountry[country] = append(byCountry[country], server)
	}

	orderedCountries := make([]string, 0, len(encountered))
	added := make(map[string]bool)
	for _, country := range nearbyTargetCountries {
		if len(byCountry[country]) > 0 {
			orderedCountries = append(orderedCountries, country)
			added[country] = true
		}
	}
	for _, country := range encountered {
		if !added[country] {
			orderedCountries = append(orderedCountries, country)
			added[country] = true
		}
	}

	selected := make([]VLESS, 0, min(limit, len(servers)))
	for rank := 0; rank < maxPerCountry && len(selected) < limit; rank++ {
		for _, country := range orderedCountries {
			if options := byCountry[country]; rank < len(options) {
				selected = append(selected, options[rank])
				if len(selected) == limit {
					break
				}
			}
		}
	}
	if len(selected) == 0 {
		return []VLESS{servers[0]}
	}
	usefulFloor := min(limit, min(minimumUsefulRoutes, len(servers)))
	if len(selected) < usefulFloor {
		chosen := make(map[string]bool, len(selected))
		for _, server := range selected {
			chosen[candidateKey(server)] = true
		}
		for _, server := range servers {
			key := candidateKey(server)
			if chosen[key] {
				continue
			}
			selected = append(selected, server)
			chosen[key] = true
			if len(selected) == usefulFloor {
				break
			}
		}
	}
	return selected
}

func countryBucket(server VLESS) string {
	code := strings.ToUpper(strings.TrimSpace(server.CountryCode))
	if len(code) == 2 {
		return code
	}
	// A trace failure must not make all otherwise YouTube-verified routes look
	// like one country and drop all but four of them. It gets an individual
	// fallback bucket until a later successful check can identify the exit.
	return "__UNKNOWN__:" + server.ID
}

// A single 256 KiB transfer is noisy. It must never promote a multi-second
// route above a usable low-latency one. Throughput breaks ties after latency.
func qualityBand(server VLESS) int {
	if server.LatencyMs <= 0 {
		return 2
	}
	// Throughput is optional because the mandatory YouTube request is the
	// publication gate. Zero means the optional speed endpoint was unavailable,
	// not that the VLESS route is slow.
	if server.LatencyMs > 1500 || (server.ThroughputKbps > 0 && server.ThroughputKbps < 1500) {
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

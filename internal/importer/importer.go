package importer

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/onetap-vpn/onetap/backend/internal/catalog"
)

type Source struct {
	Name     string
	URL      string
	MaxBytes int64
}

type MutableStore interface {
	Replace(source string, candidates []catalog.VLESS) error
}

// Checker proves that a restricted VLESS model can carry an HTTPS request.
// The caller must run it in an isolated, resource-limited worker.
type Checker interface {
	Probe(context.Context, catalog.VLESS) (catalog.ProbeMetrics, error)
}

// Runner uses validators so source polling does not needlessly download unchanged subscriptions.
// It only swaps the catalog after parsing at least one supported VLESS configuration.
type Runner struct {
	client        *http.Client
	store         MutableStore
	sources       []Source
	mu            sync.Mutex
	cache         map[string]cachedSource
	checker       Checker
	parallelism   int
	maxCandidates int
}
type cachedSource struct {
	etag, modified string
	lines          []string
}

// candidateSampleSlot matches the normal scheduled refresh. Each scheduled
// run therefore advances to the next deterministic slice rather than skipping
// through a pattern that can leave part of a large feed untested for longer.
const (
	candidateSampleSlot = 15 * time.Minute
	// Free feeds can suddenly grow to many megabytes. The checker needs a
	// rotating shortlist, not an unbounded mirror of every upstream database.
	defaultSourceMaxBytes   = 1 << 20
	maxSourceLines          = 6000
	scheduledCandidateLimit = 48
	retainedCandidateSlots  = 36
)

func New(store MutableStore, sources []Source) *Runner {
	// Keep a refresh bounded: candidates are Xray processes, not cheap TCP dials.
	// Six checks are small enough for the pilot host and let the full queue finish
	// well inside the fifteen-minute refresh window.
	return &Runner{client: &http.Client{Timeout: 12 * time.Second}, store: store, sources: sources, cache: map[string]cachedSource{}, parallelism: 6}
}

func (r *Runner) WithChecker(checker Checker) *Runner { r.checker = checker; return r }

// WithMaxCandidates bounds costly Xray processes in short-lived workers such
// as GitHub Actions. A zero value leaves the input unbounded.
func (r *Runner) WithMaxCandidates(limit int) *Runner {
	r.maxCandidates = limit
	return r
}

// ScheduledCandidateLimit is deliberately small enough that one CI run cannot
// turn a public feed update into a burst of long-lived Xray processes.
func ScheduledCandidateLimit() int { return scheduledCandidateLimit }

func (r *Runner) Refresh(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var all []string
	var changed bool
	for _, source := range r.sources {
		lines, updated, err := r.fetch(ctx, source)
		if err != nil {
			all = append(all, r.cache[source.URL].lines...)
			continue
		}
		if updated {
			changed = true
		}
		all = append(all, lines...)
	}
	// With a checker installed, a 304 means the source list did not change, not
	// that its servers are still alive. Re-probe the cached candidates before
	// extending the signed catalog.
	if !changed && r.checker == nil {
		return nil
	}
	candidates := make([]catalog.VLESS, 0, len(all))
	// Recheck the published pool first, even if a source is temporarily down.
	// These entries receive new expiry only after a new successful probe.
	if saved, ok := r.store.(interface{ Current() catalog.SignedCatalog }); ok && r.checker != nil {
		for _, server := range saved.Current().Payload.Servers {
			if server.Type == "tcp" {
				candidates = append(candidates, server)
			}
		}
	}
	seen := make(map[string]bool)
	for _, server := range candidates {
		seen[catalog.RouteKey(server)] = true
	}
	var incoming []catalog.VLESS
	for _, line := range all {
		if server, err := catalog.ParseVLESS(line, "upstream"); err == nil {
			key := catalog.RouteKey(server)
			if !seen[key] {
				incoming = append(incoming, server)
				seen[key] = true
			}
		}
	}
	if len(candidates)+len(incoming) == 0 {
		return fmt.Errorf("upstream update had no valid VLESS configurations")
	}
	if r.maxCandidates > 0 {
		candidates = selectRefreshCandidates(candidates, incoming, r.maxCandidates, time.Now().UTC())
	} else {
		candidates = append(candidates, incoming...)
	}
	if r.checker != nil {
		candidates = r.check(ctx, candidates)
	}
	if len(candidates) == 0 {
		return fmt.Errorf("no VLESS configurations passed the HTTPS probe")
	}
	return r.store.Replace("public-vless-feeds", candidates)
}

// sampleCandidates walks the complete upstream list instead of only taking its
// first entries. This keeps a bounded worker from favouring the first country
// or the first source whenever a subscription is large.
func sampleCandidates(candidates []catalog.VLESS, limit int) []catalog.VLESS {
	return sampleCandidatesAt(candidates, limit, time.Now().UTC())
}

// selectRefreshCandidates keeps most slots for the current signed pool while
// rotating both it and new upstream candidates on every quarter-hour slot.
// This prevents a huge feed from crowding out proven routes and prevents the
// first page of either group from being retried forever.
func selectRefreshCandidates(existing, incoming []catalog.VLESS, limit int, now time.Time) []catalog.VLESS {
	if limit <= 0 {
		return nil
	}
	retain := min(limit, retainedCandidateSlots)
	selected := sampleCandidatesAt(existing, retain, now)
	if len(selected) < retain {
		selected = append(selected, sampleWithoutRoutes(incoming, selected, retain-len(selected), now)...)
	}
	if len(selected) < limit {
		selected = append(selected, sampleWithoutRoutes(incoming, selected, limit-len(selected), now)...)
	}
	if len(selected) < limit {
		selected = append(selected, sampleWithoutRoutes(existing, selected, limit-len(selected), now)...)
	}
	return selected
}

func sampleWithoutRoutes(candidates, excluded []catalog.VLESS, limit int, now time.Time) []catalog.VLESS {
	if limit <= 0 {
		return nil
	}
	seen := make(map[string]bool, len(excluded))
	for _, server := range excluded {
		seen[catalog.RouteKey(server)] = true
	}
	remaining := make([]catalog.VLESS, 0, len(candidates))
	for _, server := range candidates {
		if !seen[catalog.RouteKey(server)] {
			remaining = append(remaining, server)
		}
	}
	return sampleCandidatesAt(remaining, limit, now)
}

// sampleCandidatesAt is slot-based rather than process-local. GitHub Actions
// starts a fresh worker on every run, so a counter in memory would reset and
// repeatedly inspect the same part of a large feed. The stride is coprime with
// the input length: adjacent slots choose a materially different, still evenly
// distributed, subset and eventually cover every candidate deterministically.
func sampleCandidatesAt(candidates []catalog.VLESS, limit int, now time.Time) []catalog.VLESS {
	if limit <= 0 || len(candidates) <= limit {
		return candidates
	}
	selected := make([]catalog.VLESS, 0, limit)
	size := len(candidates)
	slot := now.UTC().Unix() / int64(candidateSampleSlot/time.Second)
	stride := coprimeRotationStride(size, limit+1)
	offset := int((slot % int64(size)) * int64(stride) % int64(size))
	for index := 0; index < limit; index++ {
		// The base keeps every one slot spread over the entire source; the
		// offset changes each refresh slot rather than crawling by one
		// position per scheduled refresh.
		position := (index*size/limit + offset) % size
		selected = append(selected, candidates[position])
	}
	return selected
}

func coprimeRotationStride(size, preferred int) int {
	if size <= 1 {
		return 0
	}
	stride := preferred % size
	if stride == 0 {
		stride = 1
	}
	for greatestCommonDivisor(stride, size) != 1 {
		stride++
		if stride == size {
			stride = 1
		}
	}
	return stride
}

func greatestCommonDivisor(left, right int) int {
	for right != 0 {
		left, right = right, left%right
	}
	return left
}

func (r *Runner) check(ctx context.Context, candidates []catalog.VLESS) []catalog.VLESS {
	limit := r.parallelism
	if limit < 1 {
		limit = 1
	}
	semaphore := make(chan struct{}, limit)
	results := make(chan catalog.VLESS, len(candidates))
	var group sync.WaitGroup
	for _, server := range candidates {
		group.Add(1)
		go func(server catalog.VLESS) {
			defer group.Done()
			select {
			case semaphore <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-semaphore }()
			// This bounds DNS validation, Xray startup and the YouTube gate as one
			// unit. A dead node must release its worker quickly instead of making
			// later candidates wait behind a long network timeout.
			probeCtx, cancel := context.WithTimeout(ctx, 9*time.Second)
			defer cancel()
			if err := catalog.ValidateResolvedPublicHost(probeCtx, server.Host); err != nil {
				return
			}
			if metrics, err := r.checker.Probe(probeCtx, server); err == nil {
				server.LatencyMs = metrics.LatencyMs
				server.ThroughputKbps = metrics.ThroughputKbps
				// A feed label is untrusted display metadata. Publish a country
				// only when the HTTPS trace actually went through this VLESS exit;
				// otherwise the clients show the route as automatic instead of
				// presenting a possibly wrong flag.
				server.CountryCode = ""
				server.CountryName = ""
				if metrics.CountryCode != "" {
					server.CountryCode = metrics.CountryCode
					server.CountryName = catalog.CountryName(metrics.CountryCode)
				}
				results <- server
			}
		}(server)
	}
	group.Wait()
	close(results)
	accepted := make([]catalog.VLESS, 0, len(candidates))
	for server := range results {
		accepted = append(accepted, server)
	}
	return accepted
}
func (r *Runner) Run(ctx context.Context, interval time.Duration) {
	_ = r.Refresh(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = r.Refresh(ctx)
		}
	}
}
func (r *Runner) fetch(ctx context.Context, source Source) ([]string, bool, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source.URL, nil)
	if err != nil {
		return nil, false, err
	}
	if v := r.cache[source.URL]; v.etag != "" {
		request.Header.Set("If-None-Match", v.etag)
		request.Header.Set("If-Modified-Since", v.modified)
	}
	response, err := r.client.Do(request)
	if err != nil {
		return nil, false, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified {
		return r.cache[source.URL].lines, false, nil
	}
	if response.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("%s returned %d", source.Name, response.StatusCode)
	}
	limit := source.MaxBytes
	if limit <= 0 {
		limit = defaultSourceMaxBytes
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(body)) > limit {
		return nil, false, fmt.Errorf("%s exceeded %d byte input limit", source.Name, limit)
	}
	lines := subscriptionLines(body)
	if len(lines) > maxSourceLines {
		lines = lines[:maxSourceLines]
	}
	r.cache[source.URL] = cachedSource{etag: response.Header.Get("ETag"), modified: response.Header.Get("Last-Modified"), lines: lines}
	return lines, true, nil
}

// Some VLESS publishers serve one URI per line while others serve the whole
// subscription as standard or URL-safe Base64. Decode only a complete feed,
// never individual URI fragments, and return plain fields for the restrictive
// parser that follows.
func subscriptionLines(body []byte) []string {
	plain := strings.Fields(string(body))
	for _, line := range plain {
		if strings.HasPrefix(strings.ToLower(line), "vless://") {
			return plain
		}
	}
	compact := strings.Join(plain, "")
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		decoded, err := encoding.DecodeString(compact)
		if err != nil {
			continue
		}
		lines := strings.Fields(string(decoded))
		for _, line := range lines {
			if strings.HasPrefix(strings.ToLower(line), "vless://") {
				return lines
			}
		}
	}
	return plain
}

func DefaultSources() []Source {
	return []Source{
		// The source's normal blacklist profile is intended for ordinary YouTube
		// access. The whitelist profile is deliberately not mixed into this pool:
		// it can be necessary on restrictive networks, but it has different routing
		// trade-offs and remains a future fallback after a phone-side probe.
		{Name: "mobile-black", URL: "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt"},
		// Both Radikal feeds remain untrusted inputs. We repeat the restrictive URI
		// parsing and isolated Xray HTTPS test before publishing either candidate.
		{Name: "radikal-fast", URL: "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/fast/configs.txt"},
		{Name: "radikal-top100", URL: "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt"},
		// TLS/REALITY-only VLESS output; unsupported transports and options are
		// rejected by ParseVLESS before any connection attempt.
		{Name: "vovaplus-secure-vless", URL: "https://raw.githubusercontent.com/VovaplusEXP/p-configs/main/Splitted-By-Protocol-Secure/vless.txt"},
		// This source checks only TCP itself, so it is never trusted directly.
		// Its candidates still go through our strict parser and YouTube gate.
		{Name: "aviamastersgh-verified", URL: "https://raw.githubusercontent.com/aviamastersgh/vpn-free-russia/main/verified_configs.txt"},
		// v2go publishes its protocol-specific VLESS feed as Base64 and validates
		// routes through embedded Xray before publishing. We decode it locally and
		// repeat our independent YouTube check.
		{Name: "v2go-vless", URL: "https://raw.githubusercontent.com/Danialsamadi/v2go/main/Splitted-By-Protocol/vless.txt"},
	}
}

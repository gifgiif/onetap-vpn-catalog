package importer

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/onetap-vpn/onetap/backend/internal/catalog"
)

type Source struct {
	Name string
	URL  string
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

func New(store MutableStore, sources []Source) *Runner {
	// Keep a refresh bounded: candidates are Xray processes, not cheap TCP dials.
	// Six checks are small enough for the pilot host and let the full queue finish
	// well inside the fifteen-minute refresh window.
	return &Runner{client: &http.Client{Timeout: 20 * time.Second}, store: store, sources: sources, cache: map[string]cachedSource{}, parallelism: 6}
}

func (r *Runner) WithChecker(checker Checker) *Runner { r.checker = checker; return r }

// WithMaxCandidates bounds costly Xray processes in short-lived workers such
// as GitHub Actions. A zero value leaves the input unbounded.
func (r *Runner) WithMaxCandidates(limit int) *Runner {
	r.maxCandidates = limit
	return r
}

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
	priorCount := len(candidates)
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
		if priorCount > r.maxCandidates {
			candidates = candidates[:r.maxCandidates]
		}
		budget := r.maxCandidates - len(candidates)
		if budget > 0 {
			candidates = append(candidates, sampleCandidates(incoming, budget)...)
		}
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
	if limit <= 0 || len(candidates) <= limit {
		return candidates
	}
	selected := make([]catalog.VLESS, 0, limit)
	step := float64(len(candidates)) / float64(limit)
	for index := 0; index < limit; index++ {
		// A new slice each 15-minute slot, including on fresh CI workers.
		position := (int(float64(index)*step) + int(time.Now().Unix()/900)%len(candidates)) % len(candidates)
		selected = append(selected, candidates[position])
	}
	return selected
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
			probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
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
	body, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return nil, false, err
	}
	lines := strings.Fields(string(body))
	r.cache[source.URL] = cachedSource{etag: response.Header.Get("ETag"), modified: response.Header.Get("Last-Modified"), lines: lines}
	return lines, true, nil
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
	}
}

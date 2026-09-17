package importer

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/onetap-vpn/onetap/backend/internal/catalog"
)

type successfulChecker struct{}

func (successfulChecker) Probe(context.Context, catalog.VLESS) (catalog.ProbeMetrics, error) {
	return catalog.ProbeMetrics{LatencyMs: 120, ThroughputKbps: 8_000, CountryCode: "DE"}, nil
}

type selectiveChecker struct{ calls map[string]int }

func (c *selectiveChecker) Probe(_ context.Context, server catalog.VLESS) (catalog.ProbeMetrics, error) {
	// Tests run with one worker to make the observation deterministic.
	c.calls[server.ID]++
	if server.ID == "dead" {
		return catalog.ProbeMetrics{}, fmt.Errorf("route down")
	}
	return catalog.ProbeMetrics{LatencyMs: 100, ThroughputKbps: 4000, CountryCode: "DE"}, nil
}

type transientChecker struct{ calls map[string]int }

func (c *transientChecker) Probe(_ context.Context, server catalog.VLESS) (catalog.ProbeMetrics, error) {
	c.calls[server.ID]++
	if c.calls[server.ID] == 1 {
		return catalog.ProbeMetrics{}, fmt.Errorf("temporary route failure")
	}
	return catalog.ProbeMetrics{LatencyMs: 110, CountryCode: "DE"}, nil
}

type cancelingChecker struct{ cancel context.CancelFunc }

func (c cancelingChecker) Probe(_ context.Context, _ catalog.VLESS) (catalog.ProbeMetrics, error) {
	c.cancel()
	return catalog.ProbeMetrics{LatencyMs: 100, CountryCode: "DE"}, nil
}

type countryChecker struct{ code string }

func (c countryChecker) Probe(context.Context, catalog.VLESS) (catalog.ProbeMetrics, error) {
	return catalog.ProbeMetrics{LatencyMs: 100, ThroughputKbps: 4_000, CountryCode: c.code}, nil
}

func TestRefreshRechecksExistingPoolWhenFeedsAreUnavailable(t *testing.T) {
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	defer source.Close()
	key, _ := catalog.GenerateSigningKey()
	store := catalog.NewMemoryStore(key)
	_ = store.Replace("old", []catalog.VLESS{
		{ID: "alive", Host: "1.1.1.1", UUID: "a", Port: 443, Security: "tls", Type: "tcp"},
		{ID: "dead", Host: "8.8.8.8", UUID: "b", Port: 443, Security: "tls", Type: "tcp"},
	})
	checker := &selectiveChecker{calls: map[string]int{}}
	runner := New(store, []Source{{Name: "test", URL: source.URL}}).WithChecker(checker)
	runner.parallelism = 1
	if err := runner.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := store.Current().Payload.Servers
	if len(got) != 1 || got[0].ID != "alive" || got[0].CountryCode != "DE" {
		t.Fatalf("invalid surviving pool: %#v", got)
	}
	if checker.calls["alive"] != 1 || checker.calls["dead"] != 2 {
		t.Fatal("published pool was not rechecked")
	}
}

func TestRefreshKeepsPreviouslyPublishedRouteAfterOneTransientProbeFailure(t *testing.T) {
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	defer source.Close()
	key, _ := catalog.GenerateSigningKey()
	store := catalog.NewMemoryStore(key)
	_ = store.Replace("old", []catalog.VLESS{{ID: "flaky", Host: "1.1.1.1", UUID: "a", Port: 443, Security: "tls", Type: "tcp"}})
	checker := &transientChecker{calls: map[string]int{}}
	runner := New(store, []Source{{Name: "test", URL: source.URL}}).WithChecker(checker)
	if err := runner.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if checker.calls["flaky"] != 2 || len(store.Current().Payload.Servers) != 1 {
		t.Fatalf("transiently failing route was not confirmed and retained: calls=%d", checker.calls["flaky"])
	}
}

func TestRefreshDeadlineCannotPublishPartialCatalog(t *testing.T) {
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	defer source.Close()
	key, _ := catalog.GenerateSigningKey()
	store := catalog.NewMemoryStore(key)
	_ = store.Replace("old", []catalog.VLESS{{ID: "alive", Host: "1.1.1.1", UUID: "a", Port: 443, Security: "tls", Type: "tcp"}})
	previousRevision := store.Current().Payload.Revision
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runner := New(store, []Source{{Name: "test", URL: source.URL}}).WithChecker(cancelingChecker{cancel: cancel})
	if err := runner.Refresh(ctx); err == nil {
		t.Fatal("canceled refresh unexpectedly succeeded")
	}
	if got := store.Current().Payload.Revision; got != previousRevision {
		t.Fatalf("partial refresh replaced revision %d with %d", previousRevision, got)
	}
}

func TestRefreshOnlyPublishesValidNonEmptyCatalog(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("vless://11111111-1111-4111-8111-111111111111@1.1.1.1:443?encryption=none&security=tls&type=tcp"))
	}))
	defer server.Close()
	key, err := catalog.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	store := catalog.NewMemoryStore(key)
	runner := New(store, []Source{{Name: "test", URL: server.URL}})
	if err := runner.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.Current().Payload.Servers) != 1 {
		t.Fatal("catalog was not published")
	}
}

func TestRefreshPublishesProbeMetrics(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("vless://11111111-1111-4111-8111-111111111111@1.1.1.1:443?encryption=none&security=tls&type=tcp"))
	}))
	defer server.Close()
	key, err := catalog.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	store := catalog.NewMemoryStore(key)
	runner := New(store, []Source{{Name: "test", URL: server.URL}}).WithChecker(successfulChecker{})
	if err := runner.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := store.Current().Payload.Servers[0]
	if got.LatencyMs != 120 || got.ThroughputKbps != 8_000 {
		t.Fatalf("probe metrics were lost: %#v", got)
	}
}

func TestRefreshPreservesSafeSourceLabelForClientRegionalPreference(t *testing.T) {
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("vless://11111111-1111-4111-8111-111111111111@1.1.1.1:443?encryption=none&security=tls&type=tcp"))
	}))
	defer feed.Close()
	key, _ := catalog.GenerateSigningKey()
	store := catalog.NewMemoryStore(key)
	runner := New(store, []Source{{Name: "mobile-black", URL: feed.URL}}).WithChecker(successfulChecker{})
	if err := runner.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := store.Current().Payload.Servers
	if len(got) != 1 || got[0].Source != "mobile-black" {
		t.Fatalf("source provenance was flattened: %#v", got)
	}
}

func TestRefreshReportContainsOnlyAggregateOperationalData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("vless://11111111-1111-4111-8111-111111111111@1.1.1.1:443?encryption=none&security=tls&type=tcp"))
	}))
	defer server.Close()
	key, _ := catalog.GenerateSigningKey()
	runner := New(catalog.NewMemoryStore(key), []Source{{Name: "test-feed", URL: server.URL}}).WithChecker(successfulChecker{})
	if err := runner.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	report := runner.Report()
	if report.Outcome != "published" || report.SourceLines != 1 || report.ParsedCandidates != 1 || report.ProbeAccepted != 1 || report.PublishedServers != 1 {
		t.Fatalf("unexpected report: %#v", report)
	}
	encoded := fmt.Sprintf("%#v", report)
	for _, forbidden := range []string{server.URL, "1.1.1.1", "11111111-1111-4111-8111-111111111111"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("report leaked sensitive route data: %s", forbidden)
		}
	}
}

func TestRefreshUsesVerifiedCountryInsteadOfFeedCountry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("vless://11111111-1111-4111-8111-111111111111@1.1.1.1:443?encryption=none&security=tls&type=tcp#%F0%9F%87%A9%F0%9F%87%AA"))
	}))
	defer server.Close()
	key, _ := catalog.GenerateSigningKey()
	store := catalog.NewMemoryStore(key)
	runner := New(store, []Source{{Name: "test", URL: server.URL}}).WithChecker(successfulChecker{})
	if err := runner.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := store.Current().Payload.Servers[0]
	if got.CountryCode != "DE" || got.CountryName != "Германия" {
		t.Fatalf("verified country did not replace the untrusted feed label: %#v", got)
	}
}

func TestRefreshDoesNotPublishExcludedVerifiedCountries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("vless://11111111-1111-4111-8111-111111111111@1.1.1.1:443?encryption=none&security=tls&type=tcp"))
	}))
	defer server.Close()
	for _, code := range []string{"SG", "IN"} {
		key, _ := catalog.GenerateSigningKey()
		store := catalog.NewMemoryStore(key)
		runner := New(store, []Source{{Name: "test", URL: server.URL}}).WithChecker(countryChecker{code: code})
		if err := runner.Refresh(context.Background()); err == nil {
			t.Fatalf("%s-only candidate should not produce a catalog", code)
		}
		report := runner.Report()
		if report.ProbeExcludedCountry != 1 || report.PublishedServers != 0 {
			t.Fatalf("unexpected exclusion report for %s: %#v", code, report)
		}
	}
}

func TestSampleCandidatesUsesDeterministicRapidSlots(t *testing.T) {
	candidates := make([]catalog.VLESS, 24)
	for index := range candidates {
		candidates[index] = catalog.VLESS{ID: fmt.Sprintf("route-%02d", index)}
	}
	start := time.Unix(0, 0).UTC()
	first := sampleCandidatesAt(candidates, 6, start)
	withinSameSlot := sampleCandidatesAt(candidates, 6, start.Add(candidateSampleSlot-time.Second))
	if !sameCandidateIDs(first, withinSameSlot) {
		t.Fatal("same sample slot returned a different candidate set")
	}

	seen := make(map[string]bool)
	for slot := 0; slot < 4; slot++ {
		for _, candidate := range sampleCandidatesAt(candidates, 6, start.Add(time.Duration(slot)*candidateSampleSlot)) {
			if seen[candidate.ID] {
				t.Fatalf("candidate %s repeated before the source was covered", candidate.ID)
			}
			seen[candidate.ID] = true
		}
	}
	if len(seen) != len(candidates) {
		t.Fatalf("got %d of %d candidates after four slots", len(seen), len(candidates))
	}
}

func TestRefreshSelectionIsBoundedDistinctAndRotates(t *testing.T) {
	existing := make([]catalog.VLESS, 40)
	incoming := make([]catalog.VLESS, 80)
	for index := range existing {
		existing[index] = catalog.VLESS{ID: fmt.Sprintf("existing-%02d", index), Host: fmt.Sprintf("existing-%02d", index)}
	}
	for index := range incoming {
		incoming[index] = catalog.VLESS{ID: fmt.Sprintf("incoming-%02d", index), Host: fmt.Sprintf("incoming-%02d", index)}
	}
	start := time.Unix(0, 0).UTC()
	first := selectRefreshCandidates(existing, incoming, scheduledCandidateLimit, start)
	second := selectRefreshCandidates(existing, incoming, scheduledCandidateLimit, start.Add(candidateSampleSlot))
	if len(first) != scheduledCandidateLimit || len(second) != scheduledCandidateLimit {
		t.Fatalf("selection was not bounded to %d: %d, %d", scheduledCandidateLimit, len(first), len(second))
	}
	for _, selection := range [][]catalog.VLESS{first, second} {
		seen := map[string]bool{}
		for _, server := range selection {
			if seen[catalog.RouteKey(server)] {
				t.Fatalf("duplicate route selected: %#v", server)
			}
			seen[catalog.RouteKey(server)] = true
		}
		for _, server := range existing {
			if !seen[catalog.RouteKey(server)] {
				t.Fatalf("published route %s disappeared without a fresh probe", server.ID)
			}
		}
	}
	if sameCandidateIDs(first, second) {
		t.Fatal("two scheduled slots selected the same routes")
	}
}

func TestRefreshSelectionRechecksFullPublishedPoolAndLeavesDiscoverySlots(t *testing.T) {
	existing := make([]catalog.VLESS, 64)
	incoming := make([]catalog.VLESS, 48)
	for index := range existing {
		existing[index] = catalog.VLESS{ID: fmt.Sprintf("existing-%02d", index), Host: fmt.Sprintf("existing-%02d", index)}
	}
	for index := range incoming {
		incoming[index] = catalog.VLESS{ID: fmt.Sprintf("incoming-%02d", index), Host: fmt.Sprintf("incoming-%02d", index)}
	}
	selected := selectRefreshCandidates(existing, incoming, scheduledCandidateLimit, time.Unix(0, 0).UTC())
	if len(selected) != scheduledCandidateLimit {
		t.Fatalf("got %d selected routes, want %d", len(selected), scheduledCandidateLimit)
	}
	seen := make(map[string]bool, len(selected))
	for _, server := range selected {
		key := catalog.RouteKey(server)
		if seen[key] {
			t.Fatalf("route %s received two probe slots", server.ID)
		}
		seen[key] = true
	}
	for _, server := range existing {
		if !seen[catalog.RouteKey(server)] {
			t.Fatalf("published route %s was not rechecked", server.ID)
		}
	}
	newRoutes := 0
	for _, server := range incoming {
		if seen[catalog.RouteKey(server)] {
			newRoutes++
		}
	}
	if newRoutes != scheduledCandidateLimit-len(existing) {
		t.Fatalf("checked %d new routes, want %d", newRoutes, scheduledCandidateLimit-len(existing))
	}
}

func TestRefreshSelectionReservesSlotsForRussiaOrientedFeeds(t *testing.T) {
	existing := make([]catalog.VLESS, 64)
	incoming := make([]catalog.VLESS, 24)
	for index := range existing {
		existing[index] = catalog.VLESS{ID: fmt.Sprintf("existing-%02d", index), Host: fmt.Sprintf("existing-%02d", index)}
	}
	for index := range incoming {
		source := "generic"
		if index < 16 {
			source = "ru-black-full"
		}
		incoming[index] = catalog.VLESS{ID: fmt.Sprintf("incoming-%02d", index), Host: fmt.Sprintf("incoming-%02d", index), Source: source}
	}
	got := selectRefreshCandidates(existing, incoming, scheduledCandidateLimit, time.Unix(0, 0).UTC())
	preferred := 0
	for _, server := range got {
		if catalog.RussiaPreferredSource(server.Source) {
			preferred++
		}
	}
	if preferred != russiaPreferredCandidateSlots {
		t.Fatalf("wanted %d Russia-oriented slots, got %d", russiaPreferredCandidateSlots, preferred)
	}
}

func TestRefreshSelectionDoesNotLetOneRussiaFeedStarveAnother(t *testing.T) {
	candidates := make([]catalog.VLESS, 0, 40)
	for index := 0; index < 30; index++ {
		candidates = append(candidates, catalog.VLESS{ID: fmt.Sprintf("aggregate-%02d", index), Host: fmt.Sprintf("aggregate-%02d", index), Source: "ru-aggregate-verified"})
	}
	for index := 0; index < 10; index++ {
		candidates = append(candidates, catalog.VLESS{ID: fmt.Sprintf("whitelist-%02d", index), Host: fmt.Sprintf("whitelist-%02d", index), Source: "ru-whitelist-mobile"})
	}
	got := samplePreferredBySource(candidates, 12, time.Unix(0, 0).UTC())
	counts := map[string]int{}
	for _, server := range got {
		counts[server.Source]++
	}
	if counts["ru-aggregate-verified"] == 0 || counts["ru-whitelist-mobile"] == 0 {
		t.Fatalf("a curated source was starved: %#v", counts)
	}
}

func TestSubscriptionLinesDecodesBase64VLESSFeed(t *testing.T) {
	uri := "vless://11111111-1111-4111-8111-111111111111@example.com:443?encryption=none&security=tls&type=tcp"
	encoded := base64.RawStdEncoding.EncodeToString([]byte(uri + "\n"))
	lines := subscriptionLines([]byte(encoded))
	if len(lines) != 1 || lines[0] != uri {
		t.Fatalf("unexpected decoded lines: %#v", lines)
	}
}

func TestSubscriptionLinesKeepsPlainFeed(t *testing.T) {
	uri := "vless://11111111-1111-4111-8111-111111111111@example.com:443?encryption=none&security=tls&type=tcp"
	lines := subscriptionLines([]byte("# comment\n" + uri + "\n"))
	if len(lines) != 3 || lines[2] != uri {
		t.Fatalf("unexpected plain lines: %#v", lines)
	}
}

func sameCandidateIDs(left, right []catalog.VLESS) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].ID != right[index].ID {
			return false
		}
	}
	return true
}

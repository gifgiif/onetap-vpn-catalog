package importer

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/onetap-vpn/onetap/backend/internal/catalog"
)

type successfulChecker struct{}

func (successfulChecker) Probe(context.Context, catalog.VLESS) (catalog.ProbeMetrics, error) {
	return catalog.ProbeMetrics{LatencyMs: 120, ThroughputKbps: 8_000}, nil
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
	if checker.calls["alive"] != 1 || checker.calls["dead"] != 1 {
		t.Fatal("published pool was not rechecked")
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

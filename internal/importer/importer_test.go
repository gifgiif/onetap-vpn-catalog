package importer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/onetap-vpn/onetap/backend/internal/catalog"
)

type successfulChecker struct{}

func (successfulChecker) Probe(context.Context, catalog.VLESS) (catalog.ProbeMetrics, error) {
	return catalog.ProbeMetrics{LatencyMs: 120, ThroughputKbps: 8_000}, nil
}

func TestRefreshOnlyPublishesValidNonEmptyCatalog(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("vless://id@1.1.1.1:443?encryption=none&security=tls&type=tcp"))
	}))
	defer server.Close()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
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
		_, _ = w.Write([]byte("vless://id@1.1.1.1:443?encryption=none&security=tls&type=tcp"))
	}))
	defer server.Close()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
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

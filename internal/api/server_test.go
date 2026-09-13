package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/onetap-vpn/onetap/backend/internal/catalog"
)

func testServer(t *testing.T) *Server {
	key, err := catalog.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	store := catalog.NewMemoryStore(key)
	if err := store.ReplaceFromLines("test", []string{"vless://11111111-1111-4111-8111-111111111111@vpn.example.com:443?encryption=none&security=tls&type=tcp"}); err != nil {
		t.Fatal(err)
	}
	return NewServer(store, Config{})
}
func TestCatalogIsAvailable(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/catalog", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("got %d", rec.Code)
	}
}
func TestPurchaseRequiresRegionAndAuth(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/payments/crypto/invoices", bytes.NewBufferString("{}"))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("got %d", rec.Code)
	}
}

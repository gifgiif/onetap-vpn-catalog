package catalog

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestStoreSignsCatalog(t *testing.T) {
	key := newTestSigningKey(t)
	store := NewMemoryStore(key)
	if err := store.ReplaceFromLines("test", []string{"vless://11111111-1111-4111-8111-111111111111@vpn.example.com:443?encryption=none&security=tls&type=tcp"}); err != nil {
		t.Fatal(err)
	}
	catalog := store.Current()
	payload, _ := json.Marshal(catalog.Payload)
	signature, _ := base64.StdEncoding.DecodeString(catalog.Signature)
	if !VerifyPayloadSignature(&key.PublicKey, payload, signature) {
		t.Fatal("invalid signature")
	}
}

func TestStoreKeepsFastestEquivalentCandidateAndRanksCatalog(t *testing.T) {
	key := newTestSigningKey(t)
	store := NewMemoryStore(key)
	if err := store.Replace("test", []VLESS{
		{ID: "slow", Host: "slow.example", Port: 443, UUID: "slow", Security: "tls", SNI: "slow.example", Type: "tcp", LatencyMs: 240},
		{ID: "duplicate-slow", Host: "same.example", Port: 443, UUID: "same", Security: "tls", SNI: "same.example", Type: "tcp", LatencyMs: 180},
		{ID: "duplicate-fast", Host: "same.example", Port: 443, UUID: "same", Security: "tls", SNI: "same.example", Type: "tcp", LatencyMs: 50},
		{ID: "fast", Host: "fast.example", Port: 443, UUID: "fast", Security: "tls", SNI: "fast.example", Type: "tcp", LatencyMs: 80},
	}); err != nil {
		t.Fatal(err)
	}
	servers := store.Current().Payload.Servers
	if len(servers) != 3 {
		t.Fatalf("got %d effective candidates, want 3", len(servers))
	}
	if servers[0].ID != "duplicate-fast" || servers[0].LatencyMs != 50 || servers[1].ID != "fast" {
		t.Fatalf("catalog was not sorted by probe latency: %#v", servers)
	}
}

func TestStoreDoesNotPromoteHighLatencyOneShotThroughput(t *testing.T) {
	key := newTestSigningKey(t)
	store := NewMemoryStore(key)
	if err := store.Replace("test", []VLESS{
		{ID: "responsive", Host: "responsive.example", Port: 443, UUID: "responsive", Security: "tls", SNI: "responsive.example", Type: "tcp", LatencyMs: 604, ThroughputKbps: 3_670},
		{ID: "slower", Host: "slower.example", Port: 443, UUID: "slower", Security: "tls", SNI: "slower.example", Type: "tcp", LatencyMs: 744, ThroughputKbps: 4_450},
		{ID: "unusable", Host: "unusable.example", Port: 443, UUID: "unusable", Security: "tls", SNI: "unusable.example", Type: "tcp", LatencyMs: 5_834, ThroughputKbps: 5_600},
	}); err != nil {
		t.Fatal(err)
	}
	got := store.Current().Payload.Servers
	if got[0].ID != "responsive" || got[1].ID != "slower" || got[2].ID != "unusable" {
		t.Fatalf("catalog should prefer viable latency before one transfer rate: %#v", got)
	}
}

func TestStoreTreatsMissingOptionalThroughputAsUnknownNotSlow(t *testing.T) {
	key := newTestSigningKey(t)
	store := NewMemoryStore(key)
	if err := store.Replace("test", []VLESS{
		{ID: "youtube-ok", Host: "youtube-ok.example", Port: 443, UUID: "youtube-ok", Security: "tls", SNI: "youtube-ok.example", Type: "tcp", LatencyMs: 130, ThroughputKbps: 0},
		{ID: "slow-speed", Host: "slow-speed.example", Port: 443, UUID: "slow-speed", Security: "tls", SNI: "slow-speed.example", Type: "tcp", LatencyMs: 100, ThroughputKbps: 900},
	}); err != nil {
		t.Fatal(err)
	}
	if got := store.Current().Payload.Servers[0].ID; got != "youtube-ok" {
		t.Fatalf("missing optional speed demoted a YouTube-verified route: %s", got)
	}
}

func TestStoreCapsCountrySkewAndRetainsNearbyExits(t *testing.T) {
	key := newTestSigningKey(t)
	store := NewMemoryStore(key)
	servers := make([]VLESS, 0)
	appendCountry := func(country string, count int) {
		for index := 0; index < count; index++ {
			id := fmt.Sprintf("%s-%02d", country, index)
			servers = append(servers, VLESS{
				ID: id, Host: id + ".example", Port: 443, UUID: id,
				Security: "tls", SNI: id + ".example", Type: "tcp",
				CountryCode: country, LatencyMs: 100 + index, ThroughputKbps: 10_000,
			})
		}
	}
	appendCountry("US", 8)
	appendCountry("NL", 6)
	for _, country := range []string{"DE", "FI", "EE", "PL", "LV", "LT", "SE"} {
		appendCountry(country, 1)
	}
	appendCountry("JP", 3)

	if err := store.Replace("test", servers); err != nil {
		t.Fatal(err)
	}
	counts := make(map[string]int)
	for _, server := range store.Current().Payload.Servers {
		counts[server.CountryCode]++
	}
	for country, count := range counts {
		if count > maxRoutesPerCountry {
			t.Fatalf("%s has %d routes, cap is %d", country, count, maxRoutesPerCountry)
		}
	}
	for _, country := range []string{"DE", "FI", "EE", "PL", "LV", "LT", "SE", "NL"} {
		if counts[country] == 0 {
			t.Fatalf("nearby country %s was squeezed out: %#v", country, counts)
		}
	}
	if counts["US"] != maxRoutesPerCountry || counts["NL"] != maxRoutesPerCountry {
		t.Fatalf("country cap was not applied: %#v", counts)
	}
}

func TestStoreCountryCapKeepsAllFreshRoutesWhenOnlyOneCountryPasses(t *testing.T) {
	key := newTestSigningKey(t)
	store := NewMemoryStore(key)
	servers := make([]VLESS, 0, 6)
	for index := 0; index < 6; index++ {
		id := fmt.Sprintf("US-%02d", index)
		servers = append(servers, VLESS{ID: id, Host: id + ".example", UUID: id, Security: "tls", SNI: id + ".example", Type: "tcp", CountryCode: "US", LatencyMs: 100})
	}
	if err := store.Replace("test", servers); err != nil {
		t.Fatal(err)
	}
	got := store.Current().Payload.Servers
	if len(got) != len(servers) {
		t.Fatalf("got %d routes, want all %d fresh fallback routes", len(got), len(servers))
	}
	for _, server := range got {
		if server.CountryCode != "US" {
			t.Fatalf("unexpected fallback country: %#v", got)
		}
	}
}

func TestStoreLeavesRoomToRecheckPublishedPoolAndDiscoverNewRoutes(t *testing.T) {
	key := newTestSigningKey(t)
	store := NewMemoryStore(key)
	servers := make([]VLESS, 0, maxCatalogServers+12)
	for index := 0; index < maxCatalogServers+12; index++ {
		id := fmt.Sprintf("route-%02d", index)
		servers = append(servers, VLESS{ID: id, Host: id + ".example", UUID: id, Security: "tls", SNI: id + ".example", Type: "tcp", LatencyMs: 100})
	}
	if err := store.Replace("test", servers); err != nil {
		t.Fatal(err)
	}
	if got := len(store.Current().Payload.Servers); got != maxCatalogServers {
		t.Fatalf("published %d routes, want the %d-route recheck cap", got, maxCatalogServers)
	}
}

func TestStoreCountryCapLimitsSingleCountryOverflowToUsefulFloor(t *testing.T) {
	key := newTestSigningKey(t)
	store := NewMemoryStore(key)
	servers := make([]VLESS, 0, 20)
	for index := 0; index < 20; index++ {
		id := fmt.Sprintf("US-overflow-%02d", index)
		servers = append(servers, VLESS{ID: id, Host: id + ".example", UUID: id, Security: "tls", SNI: id + ".example", Type: "tcp", CountryCode: "US", LatencyMs: 100})
	}
	if err := store.Replace("test", servers); err != nil {
		t.Fatal(err)
	}
	if got := len(store.Current().Payload.Servers); got != minimumUsefulRoutes {
		t.Fatalf("got %d routes, want controlled fresh overflow of %d", got, minimumUsefulRoutes)
	}
}

func TestStoreDoesNotDropVerifiedRoutesWhenCountryTraceIsUnavailable(t *testing.T) {
	key := newTestSigningKey(t)
	store := NewMemoryStore(key)
	servers := make([]VLESS, 0, 6)
	for index := 0; index < 6; index++ {
		id := fmt.Sprintf("unknown-%02d", index)
		servers = append(servers, VLESS{ID: id, Host: id + ".example", UUID: id, Security: "tls", SNI: id + ".example", Type: "tcp", LatencyMs: 100})
	}
	if err := store.Replace("test", servers); err != nil {
		t.Fatal(err)
	}
	if got := len(store.Current().Payload.Servers); got != len(servers) {
		t.Fatalf("optional country trace dropped %d of %d verified routes", len(servers)-got, len(servers))
	}
}

func TestStorePublishesFreshSurvivorsEvenWhenCountryCountCollapses(t *testing.T) {
	key := newTestSigningKey(t)
	store := NewMemoryStore(key)
	now := time.Now().UTC()
	store.current = SignedCatalog{Payload: Catalog{
		Revision:  7,
		IssuedAt:  now,
		ExpiresAt: now.Add(6 * time.Hour),
		Servers: []VLESS{
			{ID: "de", CountryCode: "DE"}, {ID: "nl", CountryCode: "NL"},
			{ID: "fr", CountryCode: "FR"}, {ID: "gb", CountryCode: "GB"},
			{ID: "us", CountryCode: "US"}, {ID: "fi", CountryCode: "FI"},
		},
	}}
	if err := store.Replace("new", []VLESS{{ID: "only-us", Host: "only-us.example", UUID: "only-us", CountryCode: "US"}}); err != nil {
		t.Fatal(err)
	}
	got := store.Current().Payload
	if got.Revision != 8 || len(got.Servers) != 1 || got.Servers[0].ID != "only-us" {
		t.Fatalf("fresh survivors were hidden by the old larger catalog: %#v", got)
	}
}

func TestEmptyUpdatePreservesLastSnapshotWithoutExtendingExpiry(t *testing.T) {
	store := NewMemoryStore(newTestSigningKey(t))
	if err := store.ReplaceFromLines("test", []string{"vless://11111111-1111-4111-8111-111111111111@1.1.1.1:443?encryption=none&security=tls&type=tcp"}); err != nil {
		t.Fatal(err)
	}
	old := store.Current()
	if err := store.Replace("empty", nil); err == nil {
		t.Fatal("empty update accepted")
	}
	next := store.Current()
	if old.Signature != next.Signature || old.Payload.ExpiresAt != next.Payload.ExpiresAt {
		t.Fatal("fallback was changed")
	}
}

func TestStoreAcceptsSmallerCatalogNearExpiry(t *testing.T) {
	key := newTestSigningKey(t)
	store := NewMemoryStore(key)
	now := time.Now().UTC()
	store.current = SignedCatalog{Payload: Catalog{
		Revision:  7,
		IssuedAt:  now.Add(-5 * time.Hour),
		ExpiresAt: now.Add(20 * time.Minute),
		Servers: []VLESS{
			{ID: "de", CountryCode: "DE"}, {ID: "nl", CountryCode: "NL"},
			{ID: "fr", CountryCode: "FR"}, {ID: "gb", CountryCode: "GB"},
			{ID: "us", CountryCode: "US"}, {ID: "fi", CountryCode: "FI"},
		},
	}}
	if err := store.Replace("new", []VLESS{{ID: "only-us", Host: "only-us.example", UUID: "only-us", CountryCode: "US"}}); err != nil {
		t.Fatal(err)
	}
	got := store.Current().Payload
	if got.Revision != 8 || len(got.Servers) != 1 {
		t.Fatalf("near-expiry catalog was not refreshed: %#v", got)
	}
}

func TestPersistentStoreRetainsSignedCatalogAcrossRestart(t *testing.T) {
	key := newTestSigningKey(t)
	path := t.TempDir() + "/revision"
	store, err := NewPersistentMemoryStore(key, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceFromLines("test", []string{"vless://11111111-1111-4111-8111-111111111111@vpn.example.com:443?encryption=none&security=tls&type=tcp"}); err != nil {
		t.Fatal(err)
	}
	want := store.Current()
	restarted, err := NewPersistentMemoryStore(key, path)
	if err != nil {
		t.Fatal(err)
	}
	got := restarted.Current()
	if got.Payload.Revision != want.Payload.Revision || len(got.Payload.Servers) != 1 || got.Signature != want.Signature {
		t.Fatalf("saved catalog was not restored: %#v", got)
	}
	payload, _ := json.Marshal(got.Payload)
	signature, _ := base64.StdEncoding.DecodeString(got.Signature)
	if !VerifyPayloadSignature(&key.PublicKey, payload, signature) {
		t.Fatal("restored catalog signature is invalid")
	}
}

func TestRussiaPreferredSourceRecognizesCuratedRussiaFeeds(t *testing.T) {
	if !RussiaPreferredSource("mobile-black") || !RussiaPreferredSource("ru-black-full") || !RussiaPreferredSource("ru-whitelist-mobile") || !RussiaPreferredSource("ru-whitelist-aggregate") || !RussiaPreferredSource("ru-aggregate-verified") {
		t.Fatal("curated Russia feeds must retain their selection hint")
	}
	if RussiaPreferredSource("wlunlocker-blacklist") {
		t.Fatal("broad reserve feed must not receive the Russia preference")
	}
	if RussiaPreferredSource("radikal-fast") {
		t.Fatal("generic feed must not receive the Russian-mobile preference")
	}
}

func newTestSigningKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

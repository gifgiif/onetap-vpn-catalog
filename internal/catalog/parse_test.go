package catalog

import "testing"

func TestParseVLESSAcceptsTLS(t *testing.T) {
	server, err := ParseVLESS("vless://11111111-1111-4111-8111-111111111111@vpn.example.com:443?encryption=none&security=tls&sni=vpn.example.com&type=tcp#🇩🇪%20Frankfurt", "test")
	if err != nil || server.Security != "tls" || server.CountryCode != "DE" {
		t.Fatalf("expected TLS server, got %#v, %v", server, err)
	}
}

func TestParseVLESSAcceptsNarrowXHTTPProfile(t *testing.T) {
	server, err := ParseVLESS("vless://11111111-1111-4111-8111-111111111111@vpn.example.com:443?encryption=none&security=tls&sni=cover.example.com&type=xhttp&host=edge.example.com&path=%2Fconnect&mode=stream-one&alpn=h2%2Chttp%2F1.1#Germany", "ru-whitelist-mobile")
	if err != nil {
		t.Fatal(err)
	}
	if server.Type != "xhttp" || server.TransportHost != "edge.example.com" || server.Path != "/connect" || server.Mode != "stream-one" || server.ALPN != "h2,http/1.1" {
		t.Fatalf("XHTTP fields were not preserved: %#v", server)
	}
}

func TestParseVLESSDefaultsXHTTPModeToAuto(t *testing.T) {
	server, err := ParseVLESS("vless://11111111-1111-4111-8111-111111111111@vpn.example.com:443?encryption=none&security=tls&sni=cover.example.com&type=xhttp&host=edge.example.com&path=%2Fconnect&alpn=h2#Germany", "ru-whitelist-mobile")
	if err != nil {
		t.Fatal(err)
	}
	if server.Mode != "auto" {
		t.Fatalf("mode = %q, want auto", server.Mode)
	}
}

func TestParseVLESSRejectsUnsafeAndUnsupported(t *testing.T) {
	for _, raw := range []string{
		"vless://id@127.0.0.1:443?encryption=none&security=tls&type=tcp",
		"vless://id@vpn.example.com:443?encryption=none&security=tls&allowInsecure=1&type=tcp",
		"vless://id@vpn.example.com:443?encryption=aes-128-gcm&security=tls&type=tcp",
		"vless://id@vpn.example.com:443?encryption=none&security=tls&type=ws&path=/secret",
		"vless://id@vpn.example.com:443?encryption=none&security=tls&type=grpc&serviceName=secret",
		"vless://11111111-1111-4111-8111-111111111111@vpn.example.com:443?encryption=none&security=tls&type=xhttp&host=edge.example.com&path=/connect&mode=invalid",
		"vless://11111111-1111-4111-8111-111111111111@vpn.example.com:443?encryption=none&security=tls&type=xhttp&host=edge.example.com&path=/connect&mode=stream-one&insecure=1",
		"vless://11111111-1111-4111-8111-111111111111@vpn.example.com:443?encryption=none&security=tls&type=xhttp&host=edge.example.com&path=/connect&mode=stream-one&extra=%7B%7D",
		"vless://id@100.64.0.1:443?encryption=none&security=tls&type=tcp",
		"vless://id@[::ffff:127.0.0.1]:443?encryption=none&security=tls&type=tcp",
	} {
		if _, err := ParseVLESS(raw, "test"); err == nil {
			t.Fatalf("expected rejection: %s", raw)
		}
	}
}

func TestEquivalentUriKeepsIdentityAcrossFeedLabels(t *testing.T) {
	a, err := ParseVLESS("vless://11111111-1111-4111-8111-111111111111@vpn.example.com:443?encryption=none&security=tls&type=tcp#Germany", "first")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseVLESS("vless://11111111-1111-4111-8111-111111111111@vpn.example.com:443?type=tcp&security=tls&encryption=none#NewName", "second")
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != b.ID {
		t.Fatal("display label changed effective route identity")
	}
}

func TestParseVLESSRejectsNonUUIDIdentity(t *testing.T) {
	if _, err := ParseVLESS("vless://nasnet@vpn.example.com:443?encryption=none&security=tls&type=tcp", "test"); err == nil {
		t.Fatal("expected non-UUID VLESS identity to be rejected")
	}
}

func TestCountryNameCoversPublishedTraceCodes(t *testing.T) {
	for code, want := range map[string]string{
		"AU": "Австралия", "HK": "Гонконг", "KR": "Южная Корея", "MD": "Молдова", "TW": "Тайвань",
	} {
		if got := CountryName(code); got != want {
			t.Fatalf("CountryName(%q) = %q, want %q", code, got, want)
		}
	}
}

func TestPublishCountryAllowedUsesExplicitWhitelist(t *testing.T) {
	for _, code := range []string{"SG", "IN", "sg", "in", "", "TW", "BR"} {
		if PublishCountryAllowed(code) {
			t.Fatalf("%q must not be published", code)
		}
	}
	for _, code := range []string{"DE", "FI", "US", "HK", "JP", "KR", "MD", "HR", "uz"} {
		if !PublishCountryAllowed(code) {
			t.Fatalf("%q should remain publishable", code)
		}
	}
}

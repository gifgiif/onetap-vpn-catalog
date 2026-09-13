package catalog

import "testing"

func TestParseVLESSAcceptsTLS(t *testing.T) {
	server, err := ParseVLESS("vless://11111111-1111-4111-8111-111111111111@vpn.example.com:443?encryption=none&security=tls&sni=vpn.example.com&type=tcp#🇩🇪%20Frankfurt", "test")
	if err != nil || server.Security != "tls" || server.CountryCode != "DE" {
		t.Fatalf("expected TLS server, got %#v, %v", server, err)
	}
}

func TestParseVLESSRejectsUnsafeAndUnsupported(t *testing.T) {
	for _, raw := range []string{
		"vless://id@127.0.0.1:443?encryption=none&security=tls&type=tcp",
		"vless://id@vpn.example.com:443?encryption=none&security=tls&allowInsecure=1&type=tcp",
		"vless://id@vpn.example.com:443?encryption=aes-128-gcm&security=tls&type=tcp",
		"vless://id@vpn.example.com:443?encryption=none&security=tls&type=ws&path=/secret",
		"vless://id@vpn.example.com:443?encryption=none&security=tls&type=grpc&serviceName=secret",
		"vless://id@100.64.0.1:443?encryption=none&security=tls&type=tcp",
		"vless://id@[::ffff:127.0.0.1]:443?encryption=none&security=tls&type=tcp",
	} {
		if _, err := ParseVLESS(raw, "test"); err == nil {
			t.Fatalf("expected rejection: %s", raw)
		}
	}
}

func TestEquivalentUriKeepsIdentityAcrossFeedLabels(t *testing.T) {
	a, err := ParseVLESS("vless://id@vpn.example.com:443?encryption=none&security=tls&type=tcp#Germany", "first")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseVLESS("vless://id@vpn.example.com:443?type=tcp&security=tls&encryption=none#NewName", "second")
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != b.ID {
		t.Fatal("display label changed effective route identity")
	}
}

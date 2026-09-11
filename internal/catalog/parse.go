package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// ParseVLESS accepts a deliberately small VLESS subset. Routing, DNS and arbitrary
// remote configuration are never imported from upstream subscriptions.
func ParseVLESS(raw, source string) (VLESS, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "vless" || u.User.Username() == "" {
		return VLESS{}, fmt.Errorf("not a VLESS URI")
	}
	if u.Hostname() == "" || u.Port() == "" {
		return VLESS{}, fmt.Errorf("server host and port are required")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return VLESS{}, fmt.Errorf("invalid port")
	}
	if err := validateHost(u.Hostname()); err != nil {
		return VLESS{}, err
	}
	q := u.Query()
	security, networkType := q.Get("security"), q.Get("type")
	if networkType == "" {
		networkType = "tcp"
	}
	if q.Get("encryption") != "none" || (security != "tls" && security != "reality") {
		return VLESS{}, fmt.Errorf("unsupported VLESS security")
	}
	if networkType != "tcp" && networkType != "grpc" && networkType != "ws" {
		return VLESS{}, fmt.Errorf("unsupported transport")
	}
	if security == "tls" && q.Get("allowInsecure") == "1" {
		return VLESS{}, fmt.Errorf("insecure TLS is forbidden")
	}
	if security == "reality" && (q.Get("pbk") == "" || q.Get("sni") == "") {
		return VLESS{}, fmt.Errorf("incomplete REALITY configuration")
	}
	sum := sha256.Sum256([]byte(raw))
	code, name := countryFromLabel(u.Fragment)
	return VLESS{ID: hex.EncodeToString(sum[:12]), Host: u.Hostname(), Port: port, UUID: u.User.Username(), Security: security, SNI: q.Get("sni"), PublicKey: q.Get("pbk"), ShortID: q.Get("sid"), Flow: q.Get("flow"), Type: networkType, Source: source, CountryCode: code, CountryName: name}, nil
}

// Country labels are advisory metadata. We only publish a country when an
// upstream label identifies it; unknown locations remain "AUTO" rather than
// pretending an address belongs to a country.
func countryFromLabel(label string) (string, string) {
	value := strings.ToUpper(label)
	for _, item := range []struct{ marker, code, name string }{
		{"🇩🇪", "DE", "Германия"}, {"🇳🇱", "NL", "Нидерланды"},
		{"🇫🇮", "FI", "Финляндия"}, {"🇸🇪", "SE", "Швеция"},
		{"🇵🇱", "PL", "Польша"}, {"🇫🇷", "FR", "Франция"},
		{"🇬🇧", "GB", "Великобритания"}, {"🇺🇸", "US", "США"},
		{"🇹🇷", "TR", "Турция"}, {"🇰🇿", "KZ", "Казахстан"},
		{"🇺🇿", "UZ", "Узбекистан"}, {"🇦🇲", "AM", "Армения"},
	} {
		if strings.Contains(label, item.marker) || strings.Contains(value, strings.ToUpper(item.name)) {
			return item.code, item.name
		}
	}
	return "", ""
}

func validateHost(host string) error {
	if ip, err := netip.ParseAddr(host); err == nil {
		return validatePublicAddress(ip)
	}
	if len(host) > 253 || strings.Contains(host, "..") || net.ParseIP(host) != nil {
		return fmt.Errorf("invalid host")
	}
	// DNS resolution is performed in an isolated importer worker before probing.
	return nil
}

// ValidateResolvedPublicHost blocks a public-looking name that resolves to a
// private address before Xray is allowed to dial it. The checker is still
// isolated at the container boundary because DNS can change after validation.
func ValidateResolvedPublicHost(ctx context.Context, host string) error {
	if ip, err := netip.ParseAddr(host); err == nil {
		return validatePublicAddress(ip)
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addresses) == 0 {
		return fmt.Errorf("could not resolve server host")
	}
	for _, address := range addresses {
		if err := validatePublicAddress(address); err != nil {
			return err
		}
	}
	return nil
}

func validatePublicAddress(ip netip.Addr) error {
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
		return fmt.Errorf("non-public IP is forbidden")
	}
	return nil
}

package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var vlessUUID = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

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
	// The Android Xray configuration only accepts UUID VLESS identities.  Keep
	// the published schema aligned with the client instead of advertising a
	// route that the client will discard before it can try it.
	if !vlessUUID.MatchString(u.User.Username()) {
		return VLESS{}, fmt.Errorf("invalid VLESS UUID")
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
	if networkType != "tcp" {
		return VLESS{}, fmt.Errorf("unsupported transport")
	}
	// v3 cannot represent WS paths, gRPC service names or TCP HTTP camouflage.
	// Reject unsupported semantics instead of silently publishing a broken route.
	if q.Get("headerType") != "" && q.Get("headerType") != "none" || q.Get("path") != "" || q.Get("serviceName") != "" {
		return VLESS{}, fmt.Errorf("unsupported transport options")
	}
	if security == "tls" && q.Get("allowInsecure") == "1" {
		return VLESS{}, fmt.Errorf("insecure TLS is forbidden")
	}
	if security == "reality" && (q.Get("pbk") == "" || q.Get("sni") == "") {
		return VLESS{}, fmt.Errorf("incomplete REALITY configuration")
	}
	code, name := countryFromLabel(u.Fragment)
	server := VLESS{Host: strings.ToLower(u.Hostname()), Port: port, UUID: u.User.Username(), Security: security, SNI: q.Get("sni"), PublicKey: q.Get("pbk"), ShortID: q.Get("sid"), Flow: q.Get("flow"), Type: networkType, Source: source, CountryCode: code, CountryName: name}
	sum := sha256.Sum256([]byte(candidateKey(server)))
	server.ID = hex.EncodeToString(sum[:12])
	return server, nil
}

// Same effective route keeps its ID when a feed renames or reorders a URI.
func RouteKey(server VLESS) string { return candidateKey(server) }

func CountryName(code string) string {
	names := map[string]string{"AU": "Австралия", "DE": "Германия", "NL": "Нидерланды", "PL": "Польша", "FI": "Финляндия", "SE": "Швеция", "FR": "Франция", "GB": "Великобритания", "US": "США", "TR": "Турция", "UZ": "Узбекистан", "KZ": "Казахстан", "AM": "Армения", "AT": "Австрия", "BE": "Бельгия", "BG": "Болгария", "HR": "Хорватия", "CY": "Кипр", "CZ": "Чехия", "DK": "Дания", "EE": "Эстония", "GR": "Греция", "HU": "Венгрия", "IE": "Ирландия", "IT": "Италия", "LV": "Латвия", "LT": "Литва", "LU": "Люксембург", "MT": "Мальта", "PT": "Португалия", "RO": "Румыния", "SK": "Словакия", "SI": "Словения", "ES": "Испания", "CH": "Швейцария", "NO": "Норвегия", "CA": "Канада", "JP": "Япония", "SG": "Сингапур", "HK": "Гонконг", "KR": "Южная Корея", "MD": "Молдова", "TW": "Тайвань"}
	if name := names[code]; name != "" {
		return name
	}
	return code
}

// PublishCountryAllowed is the explicit list of exit locations available in
// the product. It prioritizes nearby European and regional exits, retaining
// the US and Canada only as distant fallbacks. A newly observed or
// unidentified country is not published by default. The check is deliberately
// applied after the HTTPS trace determines the actual exit country, rather
// than trusting an upstream URI label.
//
// This is a practical quality and product filter, not a security guarantee:
// a server operator can be untrustworthy in any country. It prevents unknown
// and unreviewed locations from silently appearing in the manual list.
func PublishCountryAllowed(code string) bool {
	_, allowed := map[string]struct{}{
		// Europe and nearby regional exits. Moldova and Croatia are intentional
		// members; geography is not used as a judgement of a server operator.
		"AM": {}, "AT": {}, "BE": {}, "BG": {}, "CH": {}, "CY": {},
		"CZ": {}, "DE": {}, "DK": {}, "EE": {}, "ES": {}, "FI": {},
		"FR": {}, "GB": {}, "GR": {}, "HR": {}, "HU": {}, "IE": {},
		"IT": {}, "KZ": {}, "LT": {}, "LU": {}, "LV": {}, "MD": {},
		"MT": {}, "NL": {}, "NO": {}, "PL": {}, "PT": {}, "RO": {},
		"SE": {}, "SI": {}, "SK": {}, "TR": {}, "UZ": {},
		// Distant emergency fallbacks.
		"CA": {}, "US": {},
	}[strings.ToUpper(strings.TrimSpace(code))]
	return allowed
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
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() ||
		netip.MustParsePrefix("100.64.0.0/10").Contains(ip) || netip.MustParsePrefix("198.18.0.0/15").Contains(ip) || netip.MustParsePrefix("192.0.0.0/24").Contains(ip) {
		return fmt.Errorf("non-public IP is forbidden")
	}
	return nil
}

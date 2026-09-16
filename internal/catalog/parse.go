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
	security, networkType := strings.ToLower(q.Get("security")), strings.ToLower(q.Get("type"))
	if networkType == "" {
		networkType = "tcp"
	}
	if q.Get("encryption") != "none" || (security != "tls" && security != "reality") {
		return VLESS{}, fmt.Errorf("unsupported VLESS security")
	}
	if q.Get("allowInsecure") == "1" || strings.EqualFold(q.Get("allowInsecure"), "true") || q.Get("insecure") == "1" || strings.EqualFold(q.Get("insecure"), "true") {
		return VLESS{}, fmt.Errorf("insecure TLS is forbidden")
	}
	if networkType != "tcp" && networkType != "xhttp" {
		return VLESS{}, fmt.Errorf("unsupported transport")
	}
	// The catalog deliberately supports only raw TCP and a narrow, auditable
	// XHTTP profile. WS, gRPC and arbitrary Xray `extra` JSON remain
	// rejected: a public subscription must never control our client routing.
	if q.Get("headerType") != "" && q.Get("headerType") != "none" || q.Get("serviceName") != "" || q.Get("extra") != "" {
		return VLESS{}, fmt.Errorf("unsupported transport options")
	}
	transportHost, path, mode, alpn := "", "", "", ""
	if networkType == "tcp" {
		if q.Get("path") != "" || q.Get("host") != "" || q.Get("mode") != "" || q.Get("alpn") != "" {
			return VLESS{}, fmt.Errorf("unsupported TCP transport options")
		}
	} else {
		transportHost = strings.ToLower(strings.TrimSpace(q.Get("host")))
		path = q.Get("path")
		mode = strings.ToLower(strings.TrimSpace(q.Get("mode")))
		if mode == "" {
			mode = "auto"
		}
		if err := validateXHTTP(transportHost, path, mode); err != nil {
			return VLESS{}, err
		}
		var err error
		alpn, err = normalizeALPN(q.Get("alpn"))
		if err != nil {
			return VLESS{}, err
		}
		if q.Get("flow") != "" {
			return VLESS{}, fmt.Errorf("XHTTP flow is unsupported")
		}
	}
	if security == "reality" && (q.Get("pbk") == "" || q.Get("sni") == "") {
		return VLESS{}, fmt.Errorf("incomplete REALITY configuration")
	}
	code, name := countryFromLabel(u.Fragment)
	server := VLESS{Host: strings.ToLower(u.Hostname()), Port: port, UUID: u.User.Username(), Security: security, SNI: q.Get("sni"), PublicKey: q.Get("pbk"), ShortID: q.Get("sid"), Flow: q.Get("flow"), Type: networkType, TransportHost: transportHost, Path: path, Mode: mode, ALPN: alpn, Source: source, CountryCode: code, CountryName: name}
	sum := sha256.Sum256([]byte(candidateKey(server)))
	server.ID = hex.EncodeToString(sum[:12])
	return server, nil
}

func validateXHTTP(host, path, mode string) error {
	if err := validateHost(host); err != nil {
		return fmt.Errorf("invalid XHTTP host: %w", err)
	}
	if len(path) == 0 || len(path) > 512 || !strings.HasPrefix(path, "/") || strings.Contains(path, "//") || strings.ContainsAny(path, "?#") {
		return fmt.Errorf("invalid XHTTP path")
	}
	for _, value := range path {
		if value <= 0x20 || value == 0x7f {
			return fmt.Errorf("invalid XHTTP path")
		}
	}
	if mode != "auto" && mode != "packet-up" && mode != "stream-up" && mode != "stream-one" {
		return fmt.Errorf("unsupported XHTTP mode")
	}
	return nil
}

func normalizeALPN(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	allowed := map[string]bool{"h2": true, "h3": true, "http/1.1": true}
	seen := map[string]bool{}
	values := make([]string, 0, 3)
	for _, part := range strings.Split(value, ",") {
		part = strings.ToLower(strings.TrimSpace(part))
		if !allowed[part] {
			return "", fmt.Errorf("unsupported ALPN")
		}
		if !seen[part] {
			seen[part] = true
			values = append(values, part)
		}
	}
	if !seen["h2"] && !seen["h3"] {
		return "", fmt.Errorf("XHTTP requires HTTP/2 or HTTP/3")
	}
	return strings.Join(values, ","), nil
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
		// Distant fallbacks, including Asian exits that can be preferable for
		// users in Russia's Far East.
		"CA": {}, "HK": {}, "JP": {}, "KR": {}, "US": {},
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

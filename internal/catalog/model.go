package catalog

import "time"

const (
	SchemaVersion = 3
	DefaultSource = "igareck/vpn-configs-for-russia"
	// KeyID is informational but lets clients distinguish a legitimate signing
	// key rotation from a replay of an older catalog under the same key.
	KeyID = "static-pilot-2026-09-ecdsa-p256"
)

type VLESS struct {
	ID             string `json:"id"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	UUID           string `json:"uuid"`
	Security       string `json:"security"`
	SNI            string `json:"sni"`
	PublicKey      string `json:"publicKey"`
	ShortID        string `json:"shortId"`
	Flow           string `json:"flow"`
	Type           string `json:"type"`
	Source         string `json:"source"`
	CountryCode    string `json:"countryCode"`
	CountryName    string `json:"countryName"`
	LatencyMs      int    `json:"latencyMs"`
	ThroughputKbps int    `json:"throughputKbps"`
}

// ProbeMetrics is collected by an isolated checker. It describes the route
// from the catalog worker through the candidate to the HTTPS probe endpoint.
// It is a ranking signal, not a promise of a user's local network speed.
type ProbeMetrics struct {
	LatencyMs      int
	ThroughputKbps int
	CountryCode    string
}

type Catalog struct {
	SchemaVersion int       `json:"schemaVersion"`
	Revision      uint64    `json:"revision"`
	IssuedAt      time.Time `json:"issuedAt"`
	ExpiresAt     time.Time `json:"expiresAt"`
	Servers       []VLESS   `json:"servers"`
}

type SignedCatalog struct {
	Payload   Catalog `json:"payload"`
	Signature string  `json:"signature"`
	KeyID     string  `json:"keyId"`
}

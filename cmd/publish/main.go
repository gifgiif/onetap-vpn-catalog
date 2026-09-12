// Command publish builds one signed static catalog. It is designed for a
// scheduled CI worker: it has no HTTP listener and never handles user traffic.
package main

import (
	"context"
	"crypto/ecdsa"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/onetap-vpn/onetap/backend/internal/catalog"
	"github.com/onetap-vpn/onetap/backend/internal/importer"
	"github.com/onetap-vpn/onetap/backend/internal/verify"
)

func main() {
	privateKey := signingKey()
	output := getenv("CATALOG_OUTPUT", "public/catalog.json")
	xrayBinary := os.Getenv("XRAY_BIN")
	if xrayBinary == "" {
		log.Fatal("XRAY_BIN is required")
	}

	store, err := catalog.NewPersistentMemoryStore(privateKey, output)
	if err != nil {
		log.Fatalf("read saved catalog: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	runner := importer.New(store, importer.DefaultSources()).
		WithMaxCandidates(96).
		WithChecker(verify.XrayChecker{Binary: xrayBinary, Timeout: 12 * time.Second})
	if err := runner.Refresh(ctx); err != nil {
		// A failed refresh must never erase a signed catalog that clients can
		// still use. The next scheduled worker tries again.
		current := store.Current().Payload
		if current.SchemaVersion == catalog.SchemaVersion && len(current.Servers) > 0 {
			log.Printf("refresh failed; keeping revision %d with %d servers: %v", current.Revision, len(current.Servers), err)
			return
		}
		log.Fatalf("no usable catalog: %v", err)
	}
	current := store.Current().Payload
	log.Printf("published revision %d with %d checked servers to %s", current.Revision, len(current.Servers), filepath.Clean(output))
}

func signingKey() *ecdsa.PrivateKey {
	encoded := os.Getenv("CATALOG_SIGNING_PRIVATE_KEY")
	if encoded == "" {
		log.Fatal("CATALOG_SIGNING_PRIVATE_KEY is required")
	}
	key, err := catalog.ParseSigningKey(encoded)
	if err != nil {
		log.Fatalf("CATALOG_SIGNING_PRIVATE_KEY is not a valid ECDSA P-256 private key: %v", err)
	}
	return key
}

func getenv(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

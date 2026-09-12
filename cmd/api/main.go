package main

import (
	"context"
	"crypto/ecdsa"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/onetap-vpn/onetap/backend/internal/api"
	"github.com/onetap-vpn/onetap/backend/internal/catalog"
	"github.com/onetap-vpn/onetap/backend/internal/importer"
	"github.com/onetap-vpn/onetap/backend/internal/verify"
)

func main() {
	privateKey, err := signingKey()
	if err != nil {
		log.Fatal(err)
	}

	var store *catalog.MemoryStore
	if path := os.Getenv("CATALOG_REVISION_FILE"); path != "" {
		store, err = catalog.NewPersistentMemoryStore(privateKey, path)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		store = catalog.NewMemoryStore(privateKey)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if os.Getenv("RUN_IMPORTER_ONLY") == "true" {
		runner, ok := configuredImporter(store)
		if !ok {
			log.Fatal("checker requires XRAY_BIN")
		}
		log.Print("OneTap catalog checker started")
		runner.Run(ctx, 15*time.Minute)
		return
	}
	server := api.NewServer(store, api.Config{
		CryptoPayToken:     os.Getenv("CRYPTO_PAY_TOKEN"),
		CryptoPayEndpoint:  os.Getenv("CRYPTO_PAY_ENDPOINT"),
		AuthPepper:         os.Getenv("AUTH_PEPPER"),
		AllowDiagnostics:   os.Getenv("ALLOW_DIAGNOSTICS") == "true",
		CatalogMirrorURL:   os.Getenv("CATALOG_MIRROR_URL"),
		EnableAccountStubs: os.Getenv("ENABLE_ACCOUNT_STUBS") == "true",
	})
	if os.Getenv("ENABLE_IMPORTER") == "true" {
		if runner, ok := configuredImporter(store); !ok {
			log.Print("WARNING: importer disabled because XRAY_BIN is not configured")
		} else {
			go runner.Run(ctx, 15*time.Minute)
		}
	}
	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":8080"
	}
	httpServer := &http.Server{Addr: listenAddr, Handler: server.Handler(), ReadHeaderTimeout: 10 * time.Second}

	go func() {
		log.Printf("OneTap backend listening on %s", httpServer.Addr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutdownCtx)
}

func configuredImporter(store *catalog.MemoryStore) (*importer.Runner, bool) {
	binary := os.Getenv("XRAY_BIN")
	if binary == "" {
		return nil, false
	}
	return importer.New(store, importer.DefaultSources()).WithChecker(verify.XrayChecker{Binary: binary, ProbeURL: os.Getenv("PROBE_URL")}), true
}

func signingKey() (*ecdsa.PrivateKey, error) {
	encoded := os.Getenv("CATALOG_SIGNING_PRIVATE_KEY")
	if encoded == "" {
		path := os.Getenv("CATALOG_SIGNING_PRIVATE_KEY_FILE")
		if path != "" {
			contents, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			encoded = strings.TrimSpace(string(contents))
		}
	}
	if encoded != "" {
		key, err := catalog.ParseSigningKey(encoded)
		if err != nil {
			return nil, &keyError{}
		}
		return key, nil
	}
	key, err := catalog.GenerateSigningKey()
	if err == nil {
		log.Print("development key generated; configure CATALOG_SIGNING_PRIVATE_KEY before deployment")
	}
	return key, err
}

type keyError struct{}

func (*keyError) Error() string {
	return "CATALOG_SIGNING_PRIVATE_KEY must be a base64 PKCS#8 ECDSA P-256 private key"
}

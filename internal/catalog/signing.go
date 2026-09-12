package catalog

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
)

// Catalog signatures use an Android-platform-compatible algorithm. ECDSA
// P-256 and SHA-256 are available on every Android version supported by the
// app, unlike Ed25519 which is only built into newer Android releases.
const SignatureAlgorithm = "ECDSA P-256 with SHA-256"

func GenerateSigningKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func ParseSigningKey(encoded string) (*ecdsa.PrivateKey, error) {
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errors.New("signing key is not base64")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse signing key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || !isP256(key.Curve) {
		return nil, errors.New("signing key must be ECDSA P-256")
	}
	return key, nil
}

func EncodeSigningKey(key *ecdsa.PrivateKey) (string, error) {
	if key == nil || !isP256(key.Curve) {
		return "", errors.New("signing key must be ECDSA P-256")
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

func EncodePublicSigningKey(key *ecdsa.PublicKey) (string, error) {
	if key == nil || !isP256(key.Curve) {
		return "", errors.New("public signing key must be ECDSA P-256")
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

func SignPayload(key *ecdsa.PrivateKey, payload []byte) ([]byte, error) {
	if key == nil || !isP256(key.Curve) {
		return nil, errors.New("signing key must be ECDSA P-256")
	}
	digest := sha256.Sum256(payload)
	return ecdsa.SignASN1(rand.Reader, key, digest[:])
}

func VerifyPayloadSignature(key *ecdsa.PublicKey, payload, signature []byte) bool {
	if key == nil || !isP256(key.Curve) {
		return false
	}
	digest := sha256.Sum256(payload)
	return ecdsa.VerifyASN1(key, digest[:], signature)
}

func isP256(curve elliptic.Curve) bool {
	return curve != nil && curve.Params().Name == elliptic.P256().Params().Name && curve.Params().BitSize == 256
}

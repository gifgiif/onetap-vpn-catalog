package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
)

func main() {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { log.Fatal(err) }
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil { log.Fatal(err) }
	output, _ := json.Marshal(map[string]string{
		"privateKey": base64.StdEncoding.EncodeToString(privateKey),
		"publicKey": base64.StdEncoding.EncodeToString(der),
	})
	fmt.Println(string(output))
}

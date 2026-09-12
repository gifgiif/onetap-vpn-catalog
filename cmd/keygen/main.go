package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/onetap-vpn/onetap/backend/internal/catalog"
)

func main() {
	privateKey, err := catalog.GenerateSigningKey()
	if err != nil {
		log.Fatal(err)
	}
	privateEncoded, err := catalog.EncodeSigningKey(privateKey)
	if err != nil {
		log.Fatal(err)
	}
	publicEncoded, err := catalog.EncodePublicSigningKey(&privateKey.PublicKey)
	if err != nil {
		log.Fatal(err)
	}
	output, _ := json.Marshal(map[string]string{
		"privateKey": privateEncoded,
		"publicKey":  publicEncoded,
	})
	fmt.Println(string(output))
}

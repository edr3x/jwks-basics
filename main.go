package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/edr3x/jwk-decoder/jwk"
)

func main() {
	keys, err := GetJWkKeys("https://www.googleapis.com/oauth2/v3/certs")
	if err != nil {
		log.Fatal(err)
	}

	for _, key := range keys {
		pubKeyPEM, err := jwk.DecodeJWKPublicKey(key)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("1: ", string(pubKeyPEM))

		encoded, err := jwk.EncodeToJWK(string(pubKeyPEM), key.Alg, key.Kid, key.Use)
		if err != nil {
			log.Fatal(err)
		}

		jwkJSON, _ := json.MarshalIndent(encoded, "", "  ")

		fmt.Println("\nJWK:\n", string(jwkJSON))

		pubKeyPEM2, err := jwk.DecodeJWKPublicKey(encoded)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("\n2:", string(pubKeyPEM2), "\n\n")
	}
}

func GetJWkKeys(url string) ([]jwk.JWK, error) {
	res, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Not OK status code")
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var jwks jwk.JWKs
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, err
	}

	return jwks.Keys, nil
}

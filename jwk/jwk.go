package jwk

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
)

type JWKs struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
	N   string `json:"n"`
	E   string `json:"e"`
	Use string `json:"use,omitempty"`
}

func DecodeJWKPublicKey(key JWK) ([]byte, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode modulus: %v", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode exponent: %v", err)
	}

	// Convert to big.Int
	n := new(big.Int).SetBytes(nBytes)
	e := int(new(big.Int).SetBytes(eBytes).Int64())

	// Create the RSA public key
	pubKey := &rsa.PublicKey{N: n, E: e}

	// Convert to PKIX, ASN.1 DER form
	pubKeyDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to marshal public key: %v", err)
	}

	// Encode to PEM format
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyDER,
	})

	return pubKeyPEM, nil
}

func EncodeToJWK(pemKey string, alg, kid, use string) (JWK, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil || block.Type != "PUBLIC KEY" {
		return JWK{}, fmt.Errorf("invalid PEM block")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return JWK{}, fmt.Errorf("failed to parse public key: %v", err)
	}

	// Assert that the key is an RSA public key
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return JWK{}, fmt.Errorf("key is not an RSA public key")
	}

	n := base64.RawURLEncoding.EncodeToString(rsaPubKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaPubKey.E)).Bytes())

	jwk := JWK{
		Kty: "RSA",
		Alg: alg,
		Kid: kid,
		N:   n,
		E:   e,
		Use: use,
	}

	return jwk, nil
}

package config

import (
	"crypto/rsa"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

var (
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
)

func LoadKeys() error {
	privateKeyData, err := os.ReadFile("config/keys/private.pem")
	if err != nil {
		return fmt.Errorf("failed to read private key file: %w", err)
	}

	// ✅ Proper assignment to global variable
	if PrivateKey, err = jwt.ParseRSAPrivateKeyFromPEM(privateKeyData); err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	publicKeyData, err := os.ReadFile("config/keys/public.pem")
	if err != nil {
		return fmt.Errorf("failed to read public key file: %w", err)
	}

	// ✅ Proper assignment to global variable
	if PublicKey, err = jwt.ParseRSAPublicKeyFromPEM(publicKeyData); err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	return nil
}

package config

import (
	"crypto/rsa"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt"
)

var (
	// JWTSecret is the secret key used to sign the JWT
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
)

func loadKyes() error {

	privateKeyData, err := os.ReadFile("config/private.pem")
	if err != nil {
		return fmt.Errorf("failed to read private key file: %w", err)
	}

	PrivateKey, err = jwt.ParseRSAPrivateKeyFromPEM(privateKeyData)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	publicKeyData, err := os.ReadFile("config/public.pem")
	if err != nil {
		return fmt.Errorf("failed to read public key file: %w", err)
	}

	PublicKey, err = jwt.ParseRSAPublicKeyFromPEM(publicKeyData)

	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}
	return nil
}

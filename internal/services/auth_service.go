package services

import (
	"time"

	"crypto/rsa"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// Load these from files (for real apps, don't hardcode them)
var (
	privateKey *rsa.PrivateKey // Load your RSA private key
	publicKey  *rsa.PublicKey  // Load your RSA public key
)

// TokenClaims defines the structure of the JWT claims
type TokenClaims struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// hash Passwords
func hashPassword(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}

// compare Passwords
func comparePassword(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

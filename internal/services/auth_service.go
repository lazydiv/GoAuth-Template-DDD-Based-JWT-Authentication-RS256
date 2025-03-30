package services

import (
	"errors"
	"fmt"
	"time"

	"crypto/rsa"

	"github.com/golang-jwt/jwt/v5"
)

// Load these from files (for real apps, don't hardcode them)
var (
	privateKey *rsa.PrivateKey // Load your RSA private key
	publicKey  *rsa.PublicKey  // Load your RSA public key
)

// TokenClaims defines the structure of the JWT claims
type TokenClaims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// Add this to auth_service.go
func InitializeKeys(privKey *rsa.PrivateKey, pubKey *rsa.PublicKey) {
	privateKey = privKey
	publicKey = pubKey
}

func GenerateJWT(userId, email, Role string) (accessToken, refreshToken string, err error) {
	// accessToken
	accesssClaims := TokenClaims{
		UserID: userId,
		Email:  email,
		Role:   Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 15)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			// Issuer:   "auth-template"
		},
	}
	accessToken, err = signToken(accesssClaims)
	if err != nil {
		return "", "", err
	}

	// refreshToken
	refreshClaims := TokenClaims{
		UserID: userId,
		Email:  email,
		Role:   Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	refreshToken, err = signToken(refreshClaims)

	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func signToken(claims TokenClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

func VerifyToken(tokenString string) (*TokenClaims, error) {
	// Check if the public key is initialized
	if publicKey == nil {
		return nil, fmt.Errorf("public key not initialized")
	}

	// Parse the token with our custom TokenClaims
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (any, error) {
		// Verify that the signing method is what we expect
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})
	if err != nil {
		// Handle JWT validation errors
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, fmt.Errorf("token expired")
		} else if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, fmt.Errorf("token not yet valid")
		} else if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			return nil, fmt.Errorf("invalid token signature")
		}
		return nil, fmt.Errorf("token validation failed: %w", err)
	}
	// Extract the claims
	claims, ok := token.Claims.(*TokenClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims format")
	}

	// Additional validation if needed (e.g., check specific claims)
	// For example, you might want to validate the issuer or audience
	// if claims.Issuer != "auth-template" {
	//     return nil, fmt.Errorf("invalid token issuer")
	// }

	return claims, nil
}

func RefreshToken(tokenString, role string) (string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (any, error) {
		return publicKey, nil
	})
	if err != nil {
		return "", err
	}

	claims := token.Claims.(*TokenClaims)
	userId := claims.UserID
	email := claims.Email

	newAccessToken, _, err := GenerateJWT(userId, email, role) // Role should come from DB
	if err != nil {
		return "", err
	}

	return newAccessToken, nil
}

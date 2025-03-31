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

	// Handle parsing errors
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, fmt.Errorf("token expired")
		} else if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, fmt.Errorf("token not yet valid")
		} else if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			return nil, fmt.Errorf("invalid token signature")
		}
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	// Ensure token is valid
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Extract claims correctly
	claims, ok := token.Claims.(*TokenClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims format")
	}

	return claims, nil
}
func RefreshToken(tokenString string) (string, error) {
	// Parse the refresh token and extract claims
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})
	if err != nil {
		return "", fmt.Errorf("failed to parse refresh token: %w", err)
	}

	// Ensure the token is valid
	if !token.Valid {
		return "", fmt.Errorf("invalid refresh token")
	}

	// Extract claims properly
	claims, ok := token.Claims.(*TokenClaims)
	if !ok {
		return "", fmt.Errorf("invalid refresh token claims format")
	}

	// Generate a new access token using the user data from the refresh token
	newAccessToken, _, err := GenerateJWT(claims.UserID, claims.Email, claims.Role)
	if err != nil {
		return "", fmt.Errorf("failed to generate new access token: %w", err)
	}

	return newAccessToken, nil
}

package main

import (
	"auth-template/internal/handlers"
	"auth-template/internal/models"
	"auth-template/internal/repository"
	"auth-template/internal/services"
	"auth-template/pkg/security"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHashAndCheckPassword tests the password hashing and verification
func TestHashAndCheckPassword(t *testing.T) {
	password := "securepassword123"

	// Test hashing
	hashedPassword, err := security.HashPassword(password)
	assert.NoError(t, err)
	assert.NotEmpty(t, hashedPassword)
	assert.NotEqual(t, password, hashedPassword)

	// Test verification with correct password
	result := security.CheckPassword(hashedPassword, password)
	assert.True(t, result)

	// Test verification with incorrect password
	result = security.CheckPassword(hashedPassword, "wrongpassword")
	assert.False(t, result)
}

// setupUserRepoTest creates a mock database for testing the UserRepo
func setupUserRepoTest(t *testing.T) (*sql.DB, sqlmock.Sqlmock, *repository.UserRepo) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)

	repo := repository.NewUserRepo(db)
	return db, mock, repo
}

// TestCreateUser tests the CreateUser function of UserRepo
func TestCreateUser(t *testing.T) {
	db, mock, repo := setupUserRepoTest(t)
	defer db.Close()

	user := &models.User{
		Email:    "test@example.com",
		Password: "password123",
		Role:     "user",
	}

	// We expect the password to be hashed, so we can't check the exact value
	mock.ExpectExec("INSERT INTO users").
		WithArgs(user.Email, sqlmock.AnyArg(), user.Role).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := repo.CreateUser(user)
	assert.NoError(t, err)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

// TestGetUserByEmail tests the GetUserbyEmail function of UserRepo
func TestGetUserByEmail(t *testing.T) {
	db, mock, repo := setupUserRepoTest(t)
	defer db.Close()

	email := "test@example.com"
	hashedPassword, _ := security.HashPassword("password123")

	rows := sqlmock.NewRows([]string{"id", "email", "password", "role"}).
		AddRow("1", email, hashedPassword, "user")

	mock.ExpectQuery("SELECT (.+) FROM users WHERE email = \\$1").
		WithArgs(email).
		WillReturnRows(rows)

	user, err := repo.GetUserbyEmail(email)
	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, email, user.Email)
	assert.Equal(t, "1", user.ID)
	assert.Equal(t, "user", user.Role)

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

// TestGetUserByEmailNotFound tests the error case for GetUserbyEmail
func TestGetUserByEmailNotFound(t *testing.T) {
	db, mock, repo := setupUserRepoTest(t)
	defer db.Close()

	email := "nonexistent@example.com"

	mock.ExpectQuery("SELECT (.+) FROM users WHERE email = \\$1").
		WithArgs(email).
		WillReturnError(sql.ErrNoRows)

	user, err := repo.GetUserbyEmail(email)
	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Contains(t, err.Error(), "user not found")

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

// setupJWTTest initializes the JWT service with test keys
func setupJWTTest(t *testing.T) {
	// Generate a test RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	publicKey := &privateKey.PublicKey
	services.InitializeKeys(privateKey, publicKey)
}

// TestGenerateAndVerifyJWT tests JWT generation and verification
func TestGenerateAndVerifyJWT(t *testing.T) {
	setupJWTTest(t)

	userId := "123"
	email := "test@example.com"
	role := "user"

	// Generate tokens
	accessToken, refreshToken, err := services.GenerateJWT(userId, email, role)
	assert.NoError(t, err)
	assert.NotEmpty(t, accessToken)
	assert.NotEmpty(t, refreshToken)

	// Verify access token
	claims, err := services.VerifyToken(accessToken)
	assert.NoError(t, err)
	assert.Equal(t, userId, claims.UserID)
	assert.Equal(t, email, claims.Email)
	assert.Equal(t, role, claims.Role)

	// Verify refresh token
	refreshClaims, err := services.VerifyToken(refreshToken)
	assert.NoError(t, err)
	assert.Equal(t, userId, refreshClaims.UserID)
}

// TestRefreshToken tests the token refresh functionality
func TestRefreshToken(t *testing.T) {
	setupJWTTest(t)

	userId := "123"
	email := "test@example.com"
	role := "user"

	// Generate initial tokens
	_, refreshToken, err := services.GenerateJWT(userId, email, role)
	assert.NoError(t, err)

	// Use the refresh token to get a new access token
	newAccessToken, err := services.RefreshToken(refreshToken)
	assert.NoError(t, err)
	assert.NotEmpty(t, newAccessToken)

	// Verify the new access token
	claims, err := services.VerifyToken(newAccessToken)
	assert.NoError(t, err)
	assert.Equal(t, userId, claims.UserID)
	assert.Equal(t, email, claims.Email)
	assert.Equal(t, role, claims.Role)
}

// setupAuthHandlerTest creates a test environment for the AuthHandler
func setupAuthHandlerTest(t *testing.T) (*gin.Engine, *sql.DB, sqlmock.Sqlmock, *repository.UserRepo) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)

	repo := repository.NewUserRepo(db)
	handler := handlers.NewAuthHandler(repo)

	gin.SetMode(gin.TestMode)
	router := gin.New()

	router.POST("/register", handler.Register)
	router.POST("/login", handler.Login)
	router.POST("/refresh", handler.RefreshToken)

	setupJWTTest(t)

	return router, db, mock, repo
}

// TestRegisterHandler tests the registration endpoint
func TestRegisterHandler(t *testing.T) {
	router, db, mock, _ := setupAuthHandlerTest(t)
	defer db.Close()

	// Setup expectations - the password will be hashed
	mock.ExpectExec("INSERT INTO users").
		WithArgs("test@example.com", sqlmock.AnyArg(), "user").
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Create request body
	reqBody := map[string]string{
		"email":    "test@example.com",
		"password": "password123",
	}
	jsonBody, _ := json.Marshal(reqBody)

	// Create request and recorder
	req, _ := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	// Serve the request
	router.ServeHTTP(resp, req)

	// Check response
	assert.Equal(t, http.StatusOK, resp.Code)

	var response map[string]string
	err := json.Unmarshal(resp.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, reqBody["email"], response["email"])

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

// TestLoginHandler tests the login endpoint
func TestLoginHandler(t *testing.T) {
	router, db, mock, _ := setupAuthHandlerTest(t)
	defer db.Close()

	email := "test@example.com"
	password := "password123"
	hashedPassword, _ := security.HashPassword(password)

	// Setup expectations for the database query
	rows := sqlmock.NewRows([]string{"id", "email", "password", "role"}).
		AddRow("1", email, hashedPassword, "user")

	mock.ExpectQuery("SELECT (.+) FROM users WHERE email = \\$1").
		WithArgs(email).
		WillReturnRows(rows)

	// Create request body
	reqBody := map[string]string{
		"email":    email,
		"password": password,
	}
	jsonBody, _ := json.Marshal(reqBody)

	// Create request and recorder
	req, _ := http.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	// Serve the request
	router.ServeHTTP(resp, req)

	// Check response
	assert.Equal(t, http.StatusOK, resp.Code)

	var response map[string]string
	err := json.Unmarshal(resp.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.NotEmpty(t, response["access_token"])
	assert.NotEmpty(t, response["refresh_token"])

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

// TestLoginHandlerInvalidPassword tests login with incorrect password
func TestLoginHandlerInvalidPassword(t *testing.T) {
	router, db, mock, _ := setupAuthHandlerTest(t)
	defer db.Close()

	email := "test@example.com"
	correctPassword := "password123"
	wrongPassword := "wrongpassword"
	hashedPassword, _ := security.HashPassword(correctPassword)

	// Setup expectations for the database query
	rows := sqlmock.NewRows([]string{"id", "email", "password", "role"}).
		AddRow("1", email, hashedPassword, "user")

	mock.ExpectQuery("SELECT (.+) FROM users WHERE email = \\$1").
		WithArgs(email).
		WillReturnRows(rows)

	// Create request body with wrong password
	reqBody := map[string]string{
		"email":    email,
		"password": wrongPassword,
	}
	jsonBody, _ := json.Marshal(reqBody)

	// Create request and recorder
	req, _ := http.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	// Serve the request
	router.ServeHTTP(resp, req)

	// Check response
	assert.Equal(t, http.StatusUnauthorized, resp.Code)

	var response map[string]string
	err := json.Unmarshal(resp.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response["error"], "invalid password")

	err = mock.ExpectationsWereMet()
	assert.NoError(t, err)
}

// TestRefreshTokenHandler tests the refresh token endpoint
func TestRefreshTokenHandler(t *testing.T) {
	router, db, _, _ := setupAuthHandlerTest(t)
	defer db.Close()

	// Generate a valid refresh token first
	_, refreshToken, err := services.GenerateJWT("1", "test@example.com", "user")
	assert.NoError(t, err)

	// Create request body
	reqBody := map[string]string{
		"refresh_token": refreshToken,
	}
	jsonBody, _ := json.Marshal(reqBody)

	// Create request and recorder
	req, _ := http.NewRequest(http.MethodPost, "/refresh", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	// Serve the request
	router.ServeHTTP(resp, req)

	// Check response
	assert.Equal(t, http.StatusOK, resp.Code)

	var response map[string]string
	err = json.Unmarshal(resp.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.NotEmpty(t, response["access_token"])
}

// TestMiddlewareAuth tests the authentication middleware
func TestMiddlewareAuth(t *testing.T) {
	// Initialize JWT service
	setupJWTTest(t)

	// Generate a valid token for testing
	accessToken, _, err := services.GenerateJWT("1", "test@example.com", "user")
	assert.NoError(t, err)

	// Setup test router with protected route
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Add middleware and protected route
	router.GET("/protected", func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(401, gin.H{"error": "Authorization header is required"})
			return
		}

		tokenParts := fmt.Sprintf("Bearer %s", accessToken)
		if authHeader != tokenParts {
			c.JSON(401, gin.H{"error": "Invalid token"})
			return
		}

		c.JSON(200, gin.H{"message": "Authenticated successfully"})
	})

	// Test with valid token
	req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	resp := httptest.NewRecorder()

	router.ServeHTTP(resp, req)

	// Check response
	assert.Equal(t, http.StatusOK, resp.Code)

	var response map[string]string
	err = json.Unmarshal(resp.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Authenticated successfully", response["message"])

	// Test without token
	req, _ = http.NewRequest(http.MethodGet, "/protected", nil)
	resp = httptest.NewRecorder()

	router.ServeHTTP(resp, req)

	// Check unauthorized response
	assert.Equal(t, http.StatusUnauthorized, resp.Code)
}

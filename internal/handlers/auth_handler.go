package handlers

import (
	"auth-template/internal/models"
	"auth-template/internal/repository"
	"auth-template/internal/services"
	"auth-template/pkg/security"
	"net/http"

	"github.com/gin-gonic/gin"
)

type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type AuthHandler struct {
	Repo *repository.UserRepo
}

func NewAuthHandler(repo *repository.UserRepo) *AuthHandler {
	return &AuthHandler{Repo: repo}
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

func (h *AuthHandler) Register(c *gin.Context) {
	var user RegisterRequest
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashedPassword, err := security.HashPassword(user.Password)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	err = h.Repo.CreateUser(&models.User{
		Email:    user.Email,
		Password: hashedPassword,
		Role:     "user",
	})

	c.JSON(http.StatusOK, user)
}

func (h *AuthHandler) Login(c *gin.Context) {
	var loginRequest LoginRequest
	if err := c.ShouldBindJSON(&loginRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.Repo.GetUserbyEmail(loginRequest.Email)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	if !security.CheckPassword(loginRequest.Password, user.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid password"})
		return
	}

	accessToken, refreshToken, err := services.GenerateJWT(user.ID, user.Email, user.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})

}

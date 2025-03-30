package middleware

import (
	"auth-template/internal/services"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(401, gin.H{"error": "Authorization header is required"})
			c.Abort()
			return
		}
		// extract the token
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			c.JSON(401, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}
		tokenString := tokenParts[1]
		claims, err := services.VerifyToken(tokenString)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		c.Set("claims", claims)
		c.Set("userID", claims.UserID)
		c.Set("email", claims.Email)
		c.Set("role", claims.Role)
		c.Next()
	}
}

func RequireRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the claims from the context (set by AuthMiddleware)
		claims, exists := c.Get("claims")
		if !exists {
			c.JSON(401, gin.H{"error": "Unauthorized: missing authentication"})
			c.Abort()
			return
		}

		// Type assertion to get the actual claims
		tokenClaims, ok := claims.(*services.TokenClaims)
		if !ok {
			c.JSON(500, gin.H{"error": "Internal server error: invalid claims format"})
			c.Abort()
			return
		}

		// Check if the user has one of the required roles
		userRole := tokenClaims.Role
		hasRequiredRole := slices.Contains(roles, userRole)

		if !hasRequiredRole {
			c.JSON(403, gin.H{"error": "Forbidden: insufficient permissions"})
			c.Abort()
			return
		}

		c.Next()
	}
}

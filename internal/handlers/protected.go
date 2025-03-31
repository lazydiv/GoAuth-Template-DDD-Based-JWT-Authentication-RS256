package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func Protected(c *gin.Context) {
	// Extract the user ID from the context
	c.JSON(http.StatusOK, gin.H{"message": "Protected route accessed"})
}

package main

import (
	"auth-template/config"
	"auth-template/internal/database"
	"auth-template/internal/handlers"
	"auth-template/internal/middleware"
	"auth-template/internal/repository"
	"auth-template/internal/services"
	"log"

	"github.com/gin-gonic/gin"
)

func initializeAuth() error {
	// Load keys from the config package
	if err := config.LoadKeys(); err != nil {
		return err
	}

	// Initialize the auth service with those keys
	services.InitializeKeys(config.PrivateKey, config.PublicKey)
	return nil

}

func main() {
	config.LoadEnv()
	if err := initializeAuth(); err != nil {
		log.Fatalf("Failed to initialize auth: %v", err)
	}
	db, err := database.Connect()

	database.CreateUsersTableMigration(db)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	app := gin.Default()
	userRepo := repository.NewUserRepo(db)

	authHandler := handlers.NewAuthHandler(userRepo)
	authRoutes := app.Group("/auth")
	{
		authRoutes.POST("/register", authHandler.Register)
		authRoutes.POST("/login", authHandler.Login)
		authRoutes.POST("/refresh", authHandler.RefreshToken)
	}

	app.GET("/test", middleware.AuthMiddleware(), handlers.Protected)

	app.GET("/admin", middleware.AuthMiddleware(), middleware.RequireRole("admin"), func(ctx *gin.Context) {
		ctx.JSON(200, gin.H{"message": "Welcome to the admin page!"})
	})

	port := config.GetEnv("PORT")
	app.Run(port)

}


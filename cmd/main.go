package main

import (
	"auth-template/config"
	"auth-template/internal/database"
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
	port := config.GetEnv("PORT")

	app := gin.Default()

	app.Run(port)

}

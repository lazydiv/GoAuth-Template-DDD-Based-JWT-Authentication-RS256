package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

// LoadEnv loads environment variables from a .env file
func LoadEnv() {
	err := godotenv.Load()
	if err != nil {
		log.Println("Warning: No .env file found, using system environment variables.")
	}
}

func GetEnv(key string, fallback ...string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	if len(fallback) > 0 {
		return fallback[0] // Correctly using the first fallback value
	}
	return "" // No fallback provided, return an empty string
}

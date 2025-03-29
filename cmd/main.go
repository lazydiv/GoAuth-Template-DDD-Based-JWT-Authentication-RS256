package main

import (
	"auth-template/config"
	"auth-template/internal/database"

	"github.com/gin-gonic/gin"
)

func main() {
	config.LoadEnv()
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

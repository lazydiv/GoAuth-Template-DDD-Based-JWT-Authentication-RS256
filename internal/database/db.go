package database

import (
	"auth-template/config"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

func Connect() (*sql.DB, error) {
	// Connect to the database
	connstr := config.GetEnv("CONNECTION_STRING")
	db, err := sql.Open("postgres", connstr)
	if err != nil {
		log.Fatal(err)
	}

	err = db.Ping()
	if err := db.Ping(); err != nil {
		db.Close() // Ensure cleanup if ping fails
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}
	fmt.Println("Connected to the database")

	// Create the users table
	return db, nil
}

func CreateUsersTableMigration(db *sql.DB) {
	query := `
  CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT NOT NULL,
      password TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
 );`

	_, err := db.Exec(query)
	if err != nil {
		log.Panic(err)
	}
	fmt.Println("Created the users table")

}

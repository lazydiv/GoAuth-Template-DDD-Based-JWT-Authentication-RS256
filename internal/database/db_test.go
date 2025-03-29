package database

import (
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
)

// Test Database Connection
func TestConnect(t *testing.T) {
	// Use a test database (change connection string if needed)
	testConnStr := "postgres://postgres:yehia@localhost:5432/gopgtest?sslmode=disable"
	os.Setenv("CONNECTION_STRING", testConnStr)

	db, err := Connect()
	assert.NoError(t, err, "Database connection should not return an error")
	assert.NotNil(t, db, "Database instance should not be nil")

	// Cleanup
	db.Close()
}

// Test Users Table Migration
func TestMigrateUsersTable(t *testing.T) {
	// Use a test database
	testConnStr := "postgres://postgres:yehia@localhost:5432/gopgtest?sslmode=disable"
	db, err := sql.Open("postgres", testConnStr)
	if err != nil {
		t.Fatalf("Failed to connect to test database: %v", err)
	}
	defer db.Close()

	// Run migration

	CreateUsersTableMigration(db)
	// Check if the table exists
	var exists bool
	query := `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'users');`
	err = db.QueryRow(query).Scan(&exists)
	assert.NoError(t, err, "Checking table existence should not return an error")
	assert.True(t, exists, "Users table should exist after migration")
}

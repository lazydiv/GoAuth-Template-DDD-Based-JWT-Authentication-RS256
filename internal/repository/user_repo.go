package repository

import (
	"auth-template/internal/models"
	"auth-template/pkg/security"
	"database/sql"
	"errors"
)

type UserRepo struct {
	db *sql.DB
}

func NewUserRepo(db *sql.DB) *UserRepo {
	return &UserRepo{db}
}

func (repo *UserRepo) CreateUser(user *models.User) error {
	hashPassword, err := security.HashPassword(user.Password)
	if err != nil {
		return err
	}
	query := "INSERT INTO users (email, password, role) VALUES ($1, $2, $3)"

	_, err = repo.db.Exec(query, user.Email, hashPassword, user.Role)
	return err
}

func (repo *UserRepo) GetUserbyEmail(email string) (*models.User, error) {
	user := &models.User{}
	err := repo.db.QueryRow("SELECT id, email, password, role FROM users WHERE email = $1", email).Scan(&user.ID, &user.Email, &user.Password, &user.Role)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("user not found")

		}
		return nil, err
	}

	return user, nil
}

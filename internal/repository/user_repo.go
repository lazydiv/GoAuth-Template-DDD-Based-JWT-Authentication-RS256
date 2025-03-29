package repository

import (
	"auth-template/internal/models"
	"database/sql"
	"errors"
)

type UserRepo struct {
	db *sql.DB
}

func NewUserRepo(db *sql.DB) *UserRepo {
	return &UserRepo{db}
}

func (repo *UserRepo) createUser(user *models.User) error {
	_, err := repo.db.Exec("INSERT INTO users (email, password) VALUES ($1, $2)", user.Email, user.Password)
	return err
}

func (repo *UserRepo) getUserbyEmail(email string) (*models.User, error) {
	user := &models.User{}
	err := repo.db.QueryRow("SELECT id, email, password FROM users WHERE email = $1", email).Scan(&user.ID, &user.Email, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("user not found")

		}
		return nil, err
	}

	return user, nil
}

package models

type User struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Password string `json:"-"`
	Role     string `json:"role"`
}

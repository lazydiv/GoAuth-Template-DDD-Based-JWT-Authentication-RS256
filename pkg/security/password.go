package security

import "golang.org/x/crypto/bcrypt"

// HashPassword hashes a plain-text password
func HashPassword(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}

// CheckPassword compares a hashed password with a plain password
func CheckPassword(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

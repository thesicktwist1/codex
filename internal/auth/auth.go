package auth

import (
	"fmt"
	"net/http"
	"net/mail"
	"strings"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

const (
	pwdMaxLen  = 24
	pwdMinLen  = 12
	nameMinLen = 8
	nameMaxLen = 18
)

func isValidEmail(email string) error {
	_, err := mail.ParseAddress(email)
	return err
}

func isValidPassword(pw string) error {
	if len(pw) < pwdMinLen || len(pw) > pwdMaxLen {
		return fmt.Errorf("password must contain between %d and %d characters", pwdMinLen, pwdMaxLen)
	}
	var hasLower, hasDigit, hasUpper bool
	for _, c := range pw {
		if c < 33 || c > 126 {
			return fmt.Errorf("invalid password character : %v", c)
		}
		switch {
		case unicode.IsDigit(c):
			hasDigit = true
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		}
	}
	if !hasLower {
		return fmt.Errorf("password must contain a lowercase character")
	}
	if !hasUpper {
		return fmt.Errorf("password must contain an uppercase character")
	}
	if !hasDigit {
		return fmt.Errorf("password must contain a digit")
	}
	return nil
}

func isValidUsername(username string) error {
	if len(username) < nameMinLen || len(username) > nameMaxLen {
		return fmt.Errorf("username must contain between %d and %d characters", nameMinLen, nameMaxLen)
	}
	for _, c := range username {
		if !unicode.IsDigit(c) || !unicode.IsLetter(c) {
			return fmt.Errorf("username must only contain digits or letters")
		}
	}
	return nil
}

func RegisterValidation(username, password, email string) error {
	if err := isValidEmail(email); err != nil {
		return err
	}
	if err := isValidPassword(password); err != nil {
		return err
	}
	if err := isValidUsername(username); err != nil {
		return err
	}
	return nil
}

func HashedPassword(password string) ([]byte, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return []byte{}, err
	}
	return hash, nil
}

func PWValidation(hash []byte, password string) error {
	return bcrypt.CompareHashAndPassword(hash, []byte(password))
}

func GetBearerToken(header http.Header) (string, error) {
	authHeader := header.Get("Authorization")
	split := strings.Split(authHeader, " ")
	if len(split) != 2 || split[0] != "Bearer" {
		return "", fmt.Errorf("malformed auth header")
	}
	return split[1], nil
}

func GetRefreshToken(header http.Header) (string, error) {
	token := 
	return "", nil
}

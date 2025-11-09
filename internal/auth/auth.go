package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/mail"
	"strings"
	"time"
	"unicode"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	pwdMaxLen  = 24
	pwdMinLen  = 12
	nameMinLen = 8
	nameMaxLen = 18
	authBearer = "Bearer"
)

var expiresIn = time.Minute * 15

// Validate a register request.
func RegisterValidation(username, password, email string) error {
	if err := isValidEmail(email); err != nil {
		return err
	}
	if err := IsValidPassword(password); err != nil {
		return err
	}
	if err := isValidUsername(username); err != nil {
		return err
	}
	return nil
}

// Hash password(string) using bcrypt.
func HashedPassword(password string) ([]byte, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return []byte{}, err
	}
	return hash, nil
}

// Extract a Bearer token from a http header
func getBearerToken(header http.Header) (string, error) {
	authHeader := header.Get("Authorization")
	split := strings.Split(authHeader, " ")
	if len(split) != 2 || split[0] != authBearer {
		return "", fmt.Errorf("malformed authorization header")
	}
	return split[1], nil
}

func JWTAuthorization(header http.Header, jwtSecret string) (string, error) {
	tokenString, err := getBearerToken(header)
	if err != nil {
		return "", err
	}
	claims := jwt.RegisteredClaims{}
	t, err := jwt.ParseWithClaims(tokenString, &claims, func(t *jwt.Token) (any, error) {
		return jwtSecret, nil
	})
	if err != nil {
		return "", err
	}
	if t.Valid {
		return "", fmt.Errorf("invalid token")
	}
	sub, err := t.Claims.GetSubject()
	if err != nil || sub == "" {
		return "", err
	}
	return sub, nil
}

func GenerateJWT(jwtSecret, userID string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   userID,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	})
	jwtToken, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}
	return strings.Join([]string{authBearer, jwtToken}, " "), nil
}

func HashedRefreshToken(token string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
}

func RefreshTokenValidation(token string, hashedToken []byte) error {
	return bcrypt.CompareHashAndPassword(hashedToken, []byte(token))
}

func GenerateRefreshToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := strings.Join([]string{"token", hex.EncodeToString(buf)}, "-")
	return token, nil
}

// Extract a refresh token from a http header
func GetRefreshToken(header http.Header) (string, error) {
	token := header.Get("refresh_token")
	if token == "" {
		return "", fmt.Errorf("refresh token not found ")
	}
	return token, nil
}

func isValidEmail(email string) error {
	_, err := mail.ParseAddress(email)
	return err
}

func IsValidPassword(pw string) error {
	if len(pw) < pwdMinLen || len(pw) > pwdMaxLen {
		return fmt.Errorf("password must contain between %d and %d characters", pwdMinLen, pwdMaxLen)
	}
	want := map[string]bool{
		"hasDigit": false,
		"hasUpper": false,
		"hasLower": false,
	}
	for _, c := range pw {
		if c < 33 || c > 126 {
			return fmt.Errorf("invalid password character : %v", c)
		}
		switch {
		case unicode.IsDigit(c):
			want["hasDigit"] = true
		case unicode.IsUpper(c):
			want["hasUpper"] = true
		case unicode.IsLower(c):
			want["hasLower"] = true
		}
	}
	var (
		b     strings.Builder
		valid = true
	)
	for m, exist := range want {
		if !exist {
			switch m {
			case "hasDigit":
				b.WriteString(",digit")
				valid = false
			case "hasUpper":
				b.WriteString(",uppercase letter")
				valid = false
			case "hasLower":
				b.WriteString(",lowercase letter")
				valid = false
			}
		}
	}
	if !valid {
		msg := fmt.Sprintf("password must contain the following characters : %v ", b.String()[1:])
		return fmt.Errorf("%s", msg)
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

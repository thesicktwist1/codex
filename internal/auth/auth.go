package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
	pwdMaxLen = 24
	pwdMinLen = 12

	titleMinLen = 4
	titleMaxLen = 48

	nameMinLen = 8
	nameMaxLen = 16

	Bearer = "Bearer"
)

var (
	expiresIn                 = time.Minute * 15
	ErrNoAuthHeaderIncluded   = errors.New("no Authorization header included")
	ErrNoRefreshTokenIncluded = errors.New("no X-Refresh-Token header included")
	ErrMalformedAuth          = errors.New("malformed authorization header")
)

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
	if authHeader == "" {
		return "", ErrNoAuthHeaderIncluded
	}
	split := strings.Split(authHeader, " ")
	if len(split) != 2 || split[0] != Bearer {
		return "", ErrMalformedAuth
	}
	return split[1], nil
}

// AuthorizeJWT extracts and validates a JWT from the http header using the given secret
func AuthorizeJWT(header http.Header, jwtSecret string) (string, error) {
	tokenString, err := getBearerToken(header)
	if err != nil {
		return "", err
	}
	claims := jwt.RegisteredClaims{}
	t, err := jwt.ParseWithClaims(tokenString, &claims,
		func(t *jwt.Token) (any, error) {
			return []byte(jwtSecret), nil
		})
	if t == nil {
		return "", err
	}
	sub, err := t.Claims.GetSubject()
	if err != nil || sub == "" {
		return "", err
	}
	issuedAt, err := t.Claims.GetIssuedAt()
	if err != nil {
		return "", err
	}
	exp, err := t.Claims.GetExpirationTime()
	if err != nil {
		return "", err
	}
	if issuedAt.After(exp.Time) || issuedAt.After(time.Now()) {
		return "", jwt.ErrTokenNotValidYet
	}
	if time.Now().After(exp.Time) && issuedAt.Before(exp.Time) {
		return sub, jwt.ErrTokenExpired
	}
	return sub, nil
}

func GenerateJWT(jwtSecret, userID string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   userID,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	})
	return token.SignedString(jwtSecret)
}

func IsValidRefreshToken(token, storedToken string, secret []byte) bool {
	hashedToken := HashRefreshToken(token, secret)
	return hmac.Equal([]byte(hashedToken), []byte(storedToken))
}

func GenerateRefreshToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func BearerJWT(token string) string {
	return strings.Join([]string{Bearer, token}, " ")
}

// Extract a refresh token from a http header
func GetRefreshToken(header http.Header) (string, error) {
	token := header.Get("X-Refresh-Token")
	if token == "" {
		return "", ErrNoRefreshTokenIncluded
	}
	return token, nil
}

func HashRefreshToken(token string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(token))
	return hex.EncodeToString(mac.Sum(nil))
}

func IsValidTitle(title string) error {
	if len(title) < titleMinLen || len(title) > titleMaxLen {
		return fmt.Errorf("titles must contain between %d and %d characters",
			titleMinLen,
			titleMaxLen)
	}
	for _, c := range title {
		if c < 32 || c > 126 {
			return fmt.Errorf("invalid title character : %v", c)
		}
	}
	return nil
}

func IsValidPassword(pw string) error {
	if len(pw) < pwdMinLen || len(pw) > pwdMaxLen {
		return fmt.Errorf("password must contain between %d and %d characters",
			pwdMinLen,
			pwdMaxLen)
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

func IsValidKey(key string) error {
	if err := isValidEmail(key); err == nil {
		return nil
	}
	if err := isValidUsername(key); err == nil {
		return nil
	}
	return fmt.Errorf("invalid key")
}

func isValidUsername(username string) error {
	if len(username) < nameMinLen || len(username) > nameMaxLen {
		return fmt.Errorf("username must contain between %d and %d characters", nameMinLen, nameMaxLen)
	}
	for _, c := range username {
		if !unicode.IsDigit(c) && !unicode.IsLetter(c) {
			return fmt.Errorf("username must only contain digits or letters")
		}
	}
	return nil
}

func isValidEmail(email string) error {
	_, err := mail.ParseAddress(email)
	return err
}

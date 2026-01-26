package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// Hash key : values
	UsersTable      = "USERS"
	TokensTable     = "TOKENS"
	KeysTable       = "KEYS"
	LibraryTable    = "LIBRARY"
	BooksTable      = "BOOKS"
	ReviewsTable    = "REVIEWS"
	CategoriesTable = "CATEGORIES"

	// Key : keys
	BookKeys    = "ALLBOOKS"
	ReviewKeys  = "ALLREVIEWS"
	ID          = "ID"
	UsernameKey = "USERNAMEKEY"
	EmailKey    = "EMAILKEY"

	timeout   = time.Second * 10
	pageLimit = 20

	Sep = ":"
)

var ErrExist = errors.New("target already exists")

func (c *Config) GenerateUserKeys(ctx context.Context, email, username string) (string, error) {
	keys := generateKeys(email, username)
	if err := c.redis.HSet(ctx, KeysTable, keys).Err(); err != nil {
		return "", err
	}
	return keys[EncodeToString([]string{email})], nil
}

func (c *Config) LookUpKeys(ctx context.Context, keys ...string) error {
	for _, key := range keys {
		encodedKey := EncodeToString([]string{key})
		exist, err := c.redis.HExists(ctx, KeysTable, encodedKey).Result()
		if err != nil {
			return err
		}
		if exist {
			return fmt.Errorf("key already exist")
		}
	}
	return nil
}

func (c *Config) DeleteUser(ctx context.Context, user *User) error {
	idKey := EncodeToString([]string{user.Email, user.Username})
	emailKey := EncodeToString([]string{user.Email})
	userKey := EncodeToString([]string{user.Username})
	if err := c.redis.HDel(ctx, UsersTable, idKey).Err(); err != nil {
		return err
	}
	if err := c.redis.HDel(ctx, TokensTable, user.ID).Err(); err != nil {
		if !errors.Is(err, redis.Nil) {
			return err
		}
	}
	return c.redis.HDel(ctx, KeysTable, emailKey, userKey).Err()
}

func (c *Config) CreateBook(ctx context.Context, book *Book) error {
	if err := c.HSetEncoded(ctx, BooksTable, book.ID, book); err != nil {
		return err
	}
	if err := c.KeysAppend(ctx, BookKeys, book.ID); err != nil {
		return err
	}
	categories := append(book.Info.Categories, book.Info.MainCategory)
	for _, cat := range categories {
		if err := c.HKeysAppend(ctx, CategoriesTable, cat, book.ID); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) createLibrary(ctx context.Context, private bool, title, userId string) (Library, error) {
	var (
		createdAt = time.Now().String()
		id        = EncodeToString([]string{title, createdAt})
		p         = boolToString(private)
	)

	libId := strings.Join([]string{p, userId, id}, Sep)
	lib := Library{
		ID:        libId,
		Owner:     userId,
		Title:     title,
		CreatedAt: createdAt,
		UpdatedAt: createdAt,
		BookIDs:   make([]string, 0),
		Private:   private,
	}
	return lib, nil
}

func EncodeToString(elems []string) string {
	key := sha256.Sum256([]byte(strings.Join(elems, "")))
	return hex.EncodeToString(key[:])[:12]
}

func parseLibraryID(id string) (string, bool, error) {
	split := strings.Split(id, Sep)
	if len(split) != 3 {
		return "", false, fmt.Errorf("malformed id")
	}
	private, err := stringToBool(split[0])
	if err != nil {
		return "", false, err
	}
	return split[1], private, nil
}

func parseReviewID(id string) (string, bool, error) {
	return "", false, nil
}

func formatId(userId, id string) string {
	return strings.Join([]string{userId, id}, Sep)
}

func stringToBool(s string) (bool, error) {
	m := map[string]bool{
		"1": true,
		"0": false,
	}
	b, exist := m[s]
	if !exist {
		return false, fmt.Errorf("invalid input : %v", s)
	}
	return b, nil
}

func boolToString(b bool) string {
	m := map[bool]string{
		false: "0",
		true:  "1",
	}
	return m[b]
}

func parseURLQueryInt(q string) (int, error) {
	var (
		n   int
		err error
	)
	if len(q) != 0 {
		n, err = strconv.Atoi(q)
		if err != nil {
			return 0, err
		}
	}
	if n < 1 {
		n = int(math.Abs(float64(n)))
	}
	return n, nil
}

func validateURLParam(param string) error {
	if len(param) == 0 {
		return fmt.Errorf("empty url parameter")
	}
	for _, c := range param {
		if c < 33 || c > 126 {
			return fmt.Errorf("invalid title character : %v", c)
		}
	}
	return nil
}

func generateKeys(email string, username string) map[string]string {
	id := EncodeToString([]string{email, username})
	emailKey := EncodeToString([]string{email})
	usernameKey := EncodeToString([]string{username})
	return map[string]string{
		emailKey:    id,
		usernameKey: id,
	}
}

func bookURL(id string) string {
	return fmt.Sprintf("https://www.googleapis.com/books/v1/volumes/%s", id)
}

func bookListURL(queries string) string {
	return fmt.Sprintf("%s", queries)
}

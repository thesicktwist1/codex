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
	testPath  = "/internal/test/book.json"

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

func (c *Config) DeleteReview(ctx context.Context, review *Review) error {
	return nil
}

func (c *Config) CreateBook(ctx context.Context, book Book) error {
	if err := c.redis.HSetNX(ctx, BooksTable, book.ID, book).Err(); err != nil {
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

func GetBooks(ctx context.Context, redis *redis.Client, IDs []string) ([]Book, error) {
	books := make([]Book, len(IDs))
	for i, id := range IDs {
		book, err := HGetDecoded[Book](ctx, redis, BooksTable, id)
		if err != nil {
			return []Book{}, err
		} else {
			books[i] = book
		}
	}
	return books, nil
}

func validateIndex(parameter string, length int) (int, error) {
	index, err := strconv.Atoi(parameter)
	if err != nil {
		return 0, err
	}
	if index >= length || index < 0 {
		return 0, fmt.Errorf("invalid index")
	}
	return index, nil
}

func EncodeToString(elems []string) string {
	key := sha256.Sum256([]byte(strings.Join(elems, "")))
	return hex.EncodeToString(key[:])[:12]
}

func parseReviewID(id string) (string, bool, error) {
	return "", false, nil
}

func formatId(userId, resourceId string) string {
	return strings.Join([]string{userId, resourceId}, Sep)
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

func parseOwnerID(id string) (string, error) {
	split := strings.Split(id, Sep)
	if len(split) != 2 {
		return "", fmt.Errorf("malformed id")
	}

	return split[0], nil
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

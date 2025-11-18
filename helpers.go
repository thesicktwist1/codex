package main

import (
	"codex/internal/auth"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
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
	LibsTable       = "LIBRARIES"
	BooksTable      = "BOOKS"
	ReviewsTable    = "REVIEWS"
	CategoriesTable = "CATEGORIES"

	// Key : keys
	BookKeys   = "ALLBOOKS"
	ReviewKeys = "ALLREVIEWS"

	timeout   = time.Second * 10
	pageLimit = 20

	Sep = ":"
)

var ErrExist = errors.New("target already exists")

func (c *Config) NewUserKeys(ctx context.Context, email, username string) (string, error) {
	id := EncodeToString([]string{email, username})
	emailKey := EncodeToString([]string{email})
	userKey := EncodeToString([]string{username})
	if err := c.redis.HSet(ctx, KeysTable, map[string]any{
		emailKey: id,
		userKey:  id,
	}).Err(); err != nil {
		return "", err
	}
	return id, nil
}

func (c *Config) authorizeRefreshToken(ctx context.Context, header http.Header, id string) error {
	token, err := auth.GetRefreshToken(header)
	if err != nil {
		return err
	}
	storedToken, err := c.redis.HGet(ctx, TokensTable, id).Result()
	if err != nil {
		return err
	}
	if !auth.IsValidRefreshToken(token, storedToken, c.hmacSecret) {
		return fmt.Errorf("invalid token")
	}
	return nil
}

func (c *Config) LookUpKeys(ctx context.Context, keys ...string) error {
	for _, key := range keys {
		if err := c.redis.HExists(ctx, KeysTable, key).Err(); err == nil {
			return fmt.Errorf("key: %v already exist", key)
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

func EncodeToString(elems []string) string {
	key := sha256.Sum256([]byte(strings.Join(elems, "")))
	return hex.EncodeToString(key[:])[:12]
}

func (c *Config) updateRefreshToken(ctx context.Context, id string) (string, error) {
	token, err := auth.GenerateRefreshToken()
	if err != nil {
		return "", err
	}
	hash := auth.HashRefreshToken(token, c.hmacSecret)
	if err := c.redis.HSet(ctx, TokensTable, map[string]any{
		id: hash,
	}).Err(); err != nil {
		return "", err
	}
	return token, nil
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

func (c *Config) CreateLibrary(ctx context.Context, private bool, title, userId string) (Library, error) {
	var (
		createdAt = time.Now().String()
		id        = EncodeToString([]string{title, createdAt})
		p         = boolToString(private)
	)
	libId := strings.Join([]string{p, userId, id}, Sep)
	if err := c.redis.HGet(ctx, LibsTable, libId).Err(); err != nil {
		if !errors.Is(err, redis.Nil) {
			return Library{}, err
		}
	} else {
		return Library{}, ErrExist
	}
	lib := Library{
		ID:        id,
		Owner:     userId,
		Title:     title,
		CreatedAt: createdAt,
		UpdatedAt: createdAt,
		BookIDs:   make([]string, 0),
		Private:   private,
	}
	if err := c.HSetEncoded(ctx, LibsTable, id, lib); err != nil {
		return Library{}, err
	}
	return lib, nil
}

func parsedId(id string) (string, bool, error) {
	split := strings.Split(id, Sep)
	if len(split) != 3 {
		return "", false, fmt.Errorf("invalid id")
	}
	private, err := stringToBool(split[2])
	if err != nil {
		return "", false, err
	}
	return split[1], private, nil
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
	if q != "" {
		n, err = strconv.Atoi(q)
		if err != nil {
			return 0, err
		}
	}
	if n < 1 {
		n = 1
	}
	return n, nil
}

func validateURLParam(param string) error {
	if param == "" {
		return fmt.Errorf("empty url parameter")
	}
	for _, c := range param {
		if c < 32 || c > 126 {
			return fmt.Errorf("invalid title character : %v", c)
		}
	}
	return nil
}

func formatFetchURLById(id string) string {
	return fmt.Sprintf("https://www.googleapis.com/books/v1/volumes/%s", id)
}

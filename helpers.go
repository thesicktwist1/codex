package main

import (
	"codex/internal/auth"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	UsersTable      = "USERS"
	TokensTable     = "TOKENS"
	KeysTable       = "KEYS"
	LibsTable       = "LIBRARIES"
	BooksTable      = "BOOKS"
	ReviewsTable    = "REVIEWS"
	AllBooksTable   = "ALLBOOKS"
	CategoriesTable = "CATEGORIES"

	timeout = time.Second * 10
	Sep     = ":"
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

func HGetDecoded[T any](ctx context.Context, rdb *redis.Client, table, key string) (T, error) {
	var payload T
	data, err := rdb.HGet(ctx, table, key).Bytes()
	if err != nil {
		return payload, err
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return payload, err
	}
	return payload, nil
}

func (c *Config) HSetEncoded(ctx context.Context, table, key string, payload any) error {
	data, err := json.Marshal(&payload)
	if err != nil {
		return err
	}
	if err := c.redis.HSet(ctx, table, key, data).Err(); err != nil {
		return err
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

func (c *Config) CreateLibrary(ctx context.Context, private bool, title, userId string) (Library, error) {
	p := "0"
	if private {
		p = "1"
	}
	createdAt := time.Now().String()
	id := EncodeToString([]string{title, createdAt})
	id = strings.Join([]string{userId, id, p}, Sep)
	if err := c.redis.HGet(ctx, LibsTable, id).Err(); err != nil {
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

func (c *Config) HScanKeys(ctx context.Context, table, key string, limit int) ([]string, error) {
	var (
		allKeys []string
		cursor  uint64
		err     error
	)
	if limit <= 0 {
		limit = math.MaxInt64
	}
	match := fmt.Sprintf("*%s*", key)
	for {
		var (
			keys []string
			next uint64
		)

		keys, next, err = c.redis.HScanNoValues(ctx, table, cursor, match, 100).Result()
		if err != nil {
			return []string{}, err
		}
		for _, key := range keys {
			allKeys = append(allKeys, key)
			if len(allKeys) >= limit {
				break
			}
		}
		if next == 0 {
			break
		}
		cursor = next
	}
	return allKeys, nil
}

func parsedLibraryID(id string) (string, bool, error) {
	split := strings.Split(id, Sep)
	if len(split) != 3 {
		return "", false, fmt.Errorf("invalid id")
	}
	private, err := boolToString(split[2])
	if err != nil {
		return "", false, err
	}
	return split[0], private, nil
}

func boolToString(s string) (bool, error) {
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

func stringToBool(b bool) string {
	m := map[bool]string{
		false: "0",
		true:  "1",
	}
	return m[b]
}

func validateURLParam(param string) error {
	if param == "" {
		return fmt.Errorf("empty url parameter")
	}
	for _, c := range param {
		if c < 33 || c > 126 {
			return fmt.Errorf("invalid title character : %v", c)
		}
	}
	return nil
}

package main

import (
	"codex/internal/auth"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	UsersTable    = "USERS"
	TokensTable   = "TOKENS"
	KeysTable     = "KEYS"
	LibsTable     = "LIBRARIES"
	BooksTable    = "BOOKS"
	TrackersTable = "TRACKERS"

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

func (c *Config) GetUser(ctx context.Context, id string) (User, error) {
	data, err := c.redis.HGet(ctx, UsersTable, id).Bytes()
	if err != nil {
		return User{}, err
	}
	var user User
	if err := json.Unmarshal(data, &user); err != nil {
		return User{}, err
	}
	return user, nil
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

func (c *Config) newRefreshToken(ctx context.Context, id string) (string, error) {
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
		ID:         id,
		Owner:      userId,
		Title:      title,
		CreatedAt:  createdAt,
		UpdatedAt:  createdAt,
		TrackerIDs: make([]string, 0),
		Private:    private,
	}
	data, err := json.Marshal(&lib)
	if err != nil {
		return Library{}, err
	}
	if err := c.redis.HSet(ctx, LibsTable, id, data).Err(); err != nil {
		return Library{}, err
	}
	return lib, nil
}

func (c *Config) GetUsersLibraries(ctx context.Context, user *User) ([]Library, error) {
	var (
		allKeys []string
		cursor  uint64
		err     error
	)
	usersMatch := strings.Join([]string{user.ID, "*"}, "")
	for {
		var (
			keys []string
			next uint64
		)
		keys, next, err = c.redis.HScan(ctx, LibsTable, cursor, usersMatch, 100).Result()
		if err != nil {
			return []Library{}, err
		}
		allKeys = append(allKeys, keys...)
		if cursor == 0 {
			break
		}
		cursor = next
	}
	libs := make([]Library, len(allKeys))
	for i, key := range allKeys {
		data, err := c.redis.HGet(ctx, LibsTable, key).Bytes()
		if err != nil {
			return []Library{}, err
		}
		var lib Library
		if err := json.Unmarshal(data, &lib); err != nil {
			return []Library{}, err
		}
		libs[i] = lib
	}
	return libs, nil
}

func (c *Config) GetBookTracker(ctx context.Context, id string) (Tracked, error) {
	data, err := c.redis.HGet(ctx, TrackersTable, id).Bytes()
	if err != nil {
		return Tracked{}, err
	}
	var tracker Tracker
	if err := json.Unmarshal(data, &tracker); err != nil {
		return Tracked{}, err
	}
	data, err = c.redis.HGet(ctx, BooksTable, tracker.BookID).Bytes()
	if err != nil {
		return Tracked{}, err
	}
	var book Book
	if err := json.Unmarshal(data, &book); err != nil {
		return Tracked{}, err
	}
	return Tracked{
		Book:    book,
		Tracker: tracker,
	}, nil
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

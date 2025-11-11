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

	"github.com/redis/go-redis/v9"
)

const (
	HUsers = "USERS"
	HToken = "TOKENS"
	HKeys  = "KEYS"
	HLibs  = "LIBRARIES"
	HBooks = "BOOKS"
)

func (c *Config) NewUserKeys(ctx context.Context, email, username string) (string, error) {
	id := EncodeToString([]string{email, username})
	emailKey := EncodeToString([]string{email})
	userKey := EncodeToString([]string{username})
	if err := c.redis.HSet(ctx, HKeys, map[string]interface{}{
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
	storedToken, err := c.redis.HGet(ctx, HToken, id).Result()
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
		if err := c.redis.HExists(ctx, HKeys, key).Err(); err == nil {
			return fmt.Errorf("key: %v already exist", key)
		}
	}
	return nil
}

func (c *Config) GetUser(ctx context.Context, id string) (User, error) {
	data, err := c.redis.HGet(ctx, HUsers, id).Bytes()
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
	if err := c.redis.HDel(ctx, HUsers, idKey).Err(); err != nil {
		return err
	}
	if err := c.redis.HDel(ctx, HToken, user.ID).Err(); err != nil {
		if !errors.Is(err, redis.Nil) {
			return err
		}
	}
	return c.redis.HDel(ctx, HKeys, emailKey, userKey).Err()
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
	if err := c.redis.HSet(ctx, HToken, map[string]any{
		id: hash,
	}).Err(); err != nil {
		return "", err
	}
	return token, nil
}

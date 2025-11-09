package main

import (
	"codex/internal/auth"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"
)

var (
	userString = "user"
	userSep    = ":"
)

func (c *Config) NewUserKeys(ctx context.Context, email, username string) (string, error) {
	id := EncodeToString([]string{email, username})
	emailKey := EncodeToString([]string{email})
	userKey := EncodeToString([]string{username})

	id = strings.Join([]string{userString, id}, userSep)

	if err := c.redis.MSet(ctx,
		emailKey, id,
		userKey, id,
	).Err(); err != nil {
		return "", err
	}
	return id, nil
}

func (c *Config) LookUpKeys(ctx context.Context, keys ...string) error {
	for _, key := range keys {
		if err := c.redis.Get(ctx, key).Err(); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) DeleteUser(ctx context.Context, user *User) error {
	idKey := EncodeToString([]string{user.Email, user.Username})
	emailKey := EncodeToString([]string{user.Email})
	userKey := EncodeToString([]string{user.Username})

	id := strings.Join([]string{userString, idKey}, userSep)
	if err := c.redis.Del(ctx, emailKey, userKey, id).Err(); err != nil {
		return err
	}
	return nil
}

func (c *Config) newRefreshToken(ctx context.Context, id string) (string, error) {
	token, err := auth.GenerateRefreshToken()
	if err != nil {
		return "", err
	}
	if err := c.redis.Set(ctx, token, id, time.Hour*72).Err(); err != nil {
		return "", err
	}
	return token, nil
}

func (c *Config) revokeRefreshToken(r *http.Request) error {
	token, err := auth.GetRefreshToken(r.Header)
	if err != nil {
		return err
	}
	return c.redis.Del(r.Context(), token).Err()
}

func EncodeToString(elems []string) string {
	key := sha256.Sum256([]byte(strings.Join(elems, "")))
	return hex.EncodeToString(key[:])[:8]
}

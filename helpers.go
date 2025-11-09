package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"strings"

	"github.com/redis/go-redis/v9"
)

var (
	userString = "user"
	userSep    = ":"
)

func (c *Config) NewKey(ctx context.Context, email, username string) (string, error) {

	id := EncodeToString([]string{email, username})
	emailKey := EncodeToString([]string{email})
	userKey := EncodeToString([]string{username})

	id = strings.Join([]string{userString, id}, userSep)

	if err := c.redis.Set(ctx, emailKey, id, 0).Err(); err != nil {
		return "", err
	}
	if err := c.redis.Set(ctx, userKey, id, 0).Err(); err != nil {
		if err := c.redis.Del(ctx, emailKey).Err(); err != nil {
			slog.Error("redis deletion error", "err", err)
		}
		return "", err
	}
	return id, nil
}

func (c *Config) LookUpKeys(ctx context.Context, keys ...string) error {
	for _, key := range keys {
		if err := c.redis.Get(ctx, key).Err(); err != redis.Nil {
			return err
		}
	}
	return nil
}

func EncodeToString(elems []string) string {
	key := sha256.Sum256([]byte(strings.Join(elems, "")))
	return hex.EncodeToString(key[:])[:8]
}

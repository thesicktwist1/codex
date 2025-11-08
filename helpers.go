package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func (c *Config) NewKey(ctx context.Context, email, username string) (string, error) {

	mainKey := EncodeToString([]string{email, username})
	emailKey := EncodeToString([]string{email})
	userKey := EncodeToString([]string{username})

	if err := c.redis.Set(ctx, emailKey, mainKey, 0).Err(); err != nil {
		return "", err
	}
	if err := c.redis.Set(ctx, userKey, mainKey, 0).Err(); err != nil {
		if err := c.redis.Del(ctx, emailKey).Err(); err != nil {
			slog.Error("redis deletion error", "err", err)
		}
		return "", err
	}
	return mainKey, nil
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

func newID(username string) string {
	return strings.Join([]string{username, uuid.New().String()[:4]}, keySep)
}

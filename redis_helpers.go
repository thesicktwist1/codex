package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/redis/go-redis/v9"
)

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

func (c *Config) KeysAppend(ctx context.Context, table, val string) error {
	allKeys, err := GetDecoded[[]string](ctx, c.redis, table)
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			return err
		}
		return c.SetEncoded(ctx, table, []string{val})
	}
	return c.SetEncoded(ctx, table, append(allKeys, val))
}

func (c *Config) KeysDelete(ctx context.Context, table, val string) error {
	allKeys, err := GetDecoded[[]string](ctx, c.redis, table)
	if err != nil {
		return err
	}
	for i, key := range allKeys {
		if key == val {
			allKeys = append(allKeys[:i], allKeys[i+1:]...)
			break
		}
	}
	return c.SetEncoded(ctx, table, allKeys)
}

func (c *Config) HKeysAppend(ctx context.Context, table, key, val string) error {
	keys, err := HGetDecoded[[]string](ctx, c.redis, table, key)
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			return err
		} else {
			return c.HSetEncoded(ctx, table, key, []string{val})
		}
	}
	keys = append(keys, val)
	return c.HSetEncoded(ctx, table, key, keys)
}

func (c *Config) HKeysDelete(ctx context.Context, table, key, val string) error {
	keys, err := HGetDecoded[[]string](ctx, c.redis, table, key)
	if err != nil {
		return err
	}
	for i, v := range keys {
		if v == val {
			keys = append(keys[:i], keys[i+1:]...)
			break
		}
	}
	return c.HSetEncoded(ctx, table, key, keys)
}

func GetDecoded[T any](ctx context.Context, rdb *redis.Client, key string) (T, error) {
	var payload T
	data, err := rdb.Get(ctx, key).Bytes()
	if err != nil {
		return payload, err
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return payload, err
	}
	return payload, nil
}

func (c *Config) SetEncoded(ctx context.Context, key string, val any) error {
	data, err := json.Marshal(val)
	if err != nil {
		return err
	}
	return c.redis.Set(ctx, key, data, 0).Err()
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
	return c.redis.HSet(ctx, table, key, data).Err()
}

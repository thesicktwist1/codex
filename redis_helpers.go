package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/redis/go-redis/v9"
)

func (c *Config) HSetEncodedNX(ctx context.Context, table, key string, payload any) (bool, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return false, err
	}
	return c.redis.HSetNX(ctx, table, key, data).Result()
}

func (c *Config) HSetEncoded(ctx context.Context, table, key string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return c.redis.HSet(ctx, table, key, data).Err()
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

func (c *Config) HScanAllKeys(ctx context.Context, table, id string) ([]string, error) {
	var (
		cursor  uint64
		allKeys []string
	)
	if c.testing {
		keys, err := c.redis.HKeys(ctx, table).Result()
		if err != nil {
			return []string{}, err
		}
		for _, key := range keys {
			if strings.Contains(key, id) {
				allKeys = append(allKeys, key)
			}
		}
		return allKeys, nil
	}
	match := fmt.Sprintf("*%s*", id)
	for {
		keys, next, err := c.redis.HScanNoValues(ctx, table, cursor, match, 100).Result()
		if err != nil {
			return nil, err
		}

		allKeys = append(allKeys, keys...)

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
			return c.SetEncoded(ctx, table, append(allKeys[:i], allKeys[i+1:]...))
		}
	}
	return nil
}

func (c *Config) HKeysDelete(ctx context.Context, table, key, val string) error {
	allKeys, err := HGetDecoded[[]string](ctx, c.redis, table, key)
	if err != nil {
		return err
	}
	for i, k := range allKeys {
		if k == val {
			return c.HSetEncoded(ctx, table, key, append(allKeys[:i], allKeys[i+1:]...))
		}
	}
	return nil
}

func (c *Config) HKeysAppend(ctx context.Context, table, key string, vals ...string) error {
	allKeys, err := HGetDecoded[[]string](ctx, c.redis, table, key)
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			return err
		} else {
			return c.HSetEncoded(ctx, table, key, append(allKeys, vals...))
		}
	}
	return c.HSetEncoded(ctx, table, key, append(allKeys, vals...))
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

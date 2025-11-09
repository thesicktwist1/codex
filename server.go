package main

import (
	"codex/internal/auth"
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"github.com/redis/go-redis/v9"
)

const (
	defaultAddr = ":8080"
)

type Config struct {
	redis     *redis.Client
	server    http.Server
	jwtSecret string
}

func NewConfig(rdb *redis.Client, opts ...OptsFunc) *Config {
	opt := defaultOpts()
	for _, o := range opts {
		o(opt)
	}
	c := &Config{
		server: http.Server{
			Addr: opt.Addr,
		},
		redis: rdb,
	}
	c.setupMux()
	return c
}

func (c *Config) revokeRefreshToken(ctx context.Context, userID string) error {
	refreshKey := auth.GetRefreshTokenKey(userID)
	if err := c.redis.Del(ctx, refreshKey).Err(); err != nil {
		if !errors.Is(err, redis.Nil) {
			return err
		}
	}
	return nil
}

func (c *Config) refreshTokenAuth(ctx context.Context, header http.Header) (string, error) {
	token, err := auth.GetRefreshToken(header)
	if err != nil {
		return "", err
	}
	id, err := c.redis.Get(ctx, token).Result()
	if err != nil {
		return "", err
	}
	return id, nil
}

func (c *Config) newRefreshToken(ctx context.Context, userID string) (string, error) {
	token, err := auth.GenerateRefreshToken()
	if err != nil {
		return "", err
	}
	hashedToken, err := auth.HashedRefreshToken(token)
	if err := c.redis.Set(ctx, string(hashedToken), userID, time.Hour*72).Err(); err != nil {
		return "", err
	}
	return token, nil
}

func (c *Config) setupMux() {
	mux := chi.NewMux()
	// Connection requests
	mux.Post("/register", c.handlerRegister)
	mux.Post("/login", c.handlerLogin)
	mux.Get("/healthz", c.handlerReadiness)

	c.server.Handler = mux
}

func (c *Config) handlerReadiness(w http.ResponseWriter, r *http.Request) {
	respondWithJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type Opts struct {
	Addr string
}

type OptsFunc func(*Opts)

func defaultOpts() *Opts {
	return &Opts{
		Addr: defaultAddr,
	}
}

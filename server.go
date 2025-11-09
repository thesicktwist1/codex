package main

import (
	"codex/internal/auth"
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
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

func (c *Config) setupMux() {
	mux := chi.NewMux()
	// connection requests
	mux.Post("/register", c.handlerRegister)
	mux.Post("/revoke", c.handlerRevokeToken)
	mux.Post("/login", c.handlerLogin)

	// authed handlers
	mux.Delete("/users", c.middlewareAuth(c.handlerDelete))

	mux.Get("/healthz", c.handlerReadiness)

	c.server.Handler = mux
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

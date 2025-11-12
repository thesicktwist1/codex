package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/redis/go-redis/v9"
)

const (
	defaultAddr = ":8080"
)

type Config struct {
	redis      *redis.Client
	server     http.Server
	jwtSecret  string
	hmacSecret []byte
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

func (c *Config) setupMux() {
	mux := chi.NewMux()
	// account handling
	mux.Post("/register", c.handlerRegisterUser)
	mux.Post("/revoke", c.middlewareAuth(c.handlerRevokeToken))
	mux.Post("/login", c.handlerLogin)
	mux.Delete("/users", c.middlewareAuth(c.handlerDeleteUser))
	mux.Get("/users", c.middlewareAuth(c.handlerGetUser))
	mux.Put("/users", c.middlewareAuth(c.handlerUpdateUser))

	// libraries handling
	mux.Post("/libraries", c.middlewareAuth(c.handlerCreateLibrary))
	mux.Get("/libraries", c.middlewareAuth(c.handlerGetUsersLibraries))
	mux.Get("/libraries/{id}", c.handlerGetLibrary)
	mux.Delete("/libraries/{id}", c.middlewareAuth(c.handlerDeleteLibrary))

	// server readiness
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

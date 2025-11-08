package main

import (
	"net/http"

	"github.com/go-chi/chi"
	"github.com/redis/go-redis/v9"
)

const (
	defaultAddr = ":8080"
)

type Config struct {
	redis  *redis.Client
	Server http.Server
}

func NewConfig(rdb *redis.Client, opts ...OptsFunc) *Config {
	opt := defaultOpts()
	for _, o := range opts {
		o(opt)
	}
	c := &Config{
		Server: http.Server{
			Addr: opt.Addr,
		},
		redis: rdb,
	}
	c.setupMux()
	return c
}

func (c *Config) setupMux() {
	mux := chi.NewMux()
	// Connection requests
	mux.Post("/register", c.handlerRegister)
	mux.Post("/login", c.handlerLogin)

	c.Server.Handler = mux
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

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
	client     http.Client
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

func (c *Config) SetJWTSecret(secret string) {
	c.jwtSecret = secret
}

func (c *Config) SetHMACSecret(secret []byte) {
	c.hmacSecret = secret
}

func (c *Config) setupMux() {
	mux := chi.NewMux()
	// account handling
	mux.Post("/register", c.handlerRegisterUser)
	mux.Post("/revoke", c.middlewareAuth(c.handlerRevokeToken))
	mux.Post("/login", c.handlerLogin)
	mux.Delete("/user", c.middlewareAuth(c.handlerDeleteUser))
	mux.Get("/user", c.middlewareAuth(c.handlerGetUser))
	mux.Put("/user", c.middlewareAuth(c.handlerUpdateUser))

	// libraries handling
	mux.Post("/libraries", c.middlewareAuth(c.handlerCreateLibrary))
	mux.Get("/libraries", c.middlewareAuth(c.handlerGetUsersLibraries))
	mux.Get("/libraries/{id}", c.handlerGetLibrary)
	mux.Delete("/libraries/{id}", c.middlewareAuth(c.handlerDeleteLibrary))

	// books handling
	mux.Get("/books", c.handlerGetBooks)
	mux.Get("/books/{id}/reviews", c.handlerGetReviewsByBookId)

	mux.Get("/book/{id}", c.handlerGetBookById)

	// reviews handling

	mux.Post("/review/{bookId}", c.middlewareAuth(c.handlerCreateReview))
	mux.Delete("/review/{bookId}", c.middlewareAuth(c.handlerDeleteReview))
	mux.Put("/review/{bookId}", c.middlewareAuth(c.handlerUpdateReview))
	mux.Get("/review/{id}", c.handlerGetReviewById)

	mux.Get("/tracked", c.middlewareAuth(c.handlerGetTracked))

	// fetch handling
	mux.Get("/fetch/book/{id}", c.handlerFetchBookById)

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

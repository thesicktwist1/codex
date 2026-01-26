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
	http.Server
	redis     *redis.Client
	jwtSecret string
	testing   bool
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
		testing: opt.Testing,
		redis:   rdb,
	}
	c.setupMux()
	return c
}

func (c *Config) SetJWTSecret(secret string) {
	c.jwtSecret = secret
}

func (c *Config) setupMux() {
	mux := chi.NewMux()
	// account handling
	mux.Post("/register", c.handlerRegisterUser)
	mux.Post("/revoke", c.middlewareAuth(c.handlerRevokeToken))
	mux.Post("/refresh", c.handlerRefresh)
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

	// server readiness
	mux.Get("/healthz", c.handlerReadiness)

	c.Server.Handler = mux
}

func (c *Config) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.Server.Handler.ServeHTTP(w, r)
}

type Opts struct {
	Addr    string
	Testing bool
}

type OptsFunc func(*Opts)

func defaultOpts() *Opts {
	return &Opts{
		Addr: defaultAddr,
	}
}

func withTesting() OptsFunc {
	return func(o *Opts) {
		o.Testing = true
	}
}

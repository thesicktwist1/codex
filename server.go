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
	mux.Get("/libraries/{libraryID}", c.handlerGetLibrary)
	mux.Delete("/libraries/{libraryID}", c.middlewareAuth(c.handlerDeleteLibrary))
	mux.Delete(
		"/libraries/{libraryID}/books/{bookIdx}",
		c.middlewareAuth(c.handlerDeleteLibraryBook),
	)
	mux.Post("/libraries/{libraryID}/books/{bookID}",
		c.middlewareAuth(c.handlerUpdateLibraryBooks),
	)

	// books handling
	mux.Get("/books", c.handlerGetBooks)
	mux.Post("/books", c.handlerCreateBook)

	mux.Get("/books/{bookID}", c.handlerGetBookById)

	// reviews handling
	mux.Get("/reviews/books/{bookID}", c.handlerGetReviewsByBookId)
	mux.Post("/reviews/{bookID}", c.middlewareAuth(c.handlerCreateReview))
	mux.Delete("/reviews/{reviewID}", c.middlewareAuth(c.handlerDeleteReview))
	mux.Put("/reviews/{reviewID}", c.middlewareAuth(c.handlerUpdateReview))
	mux.Get("/reviews/{reviewID}", c.handlerGetReviewById)

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

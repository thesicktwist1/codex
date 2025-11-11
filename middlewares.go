package main

import (
	"codex/internal/auth"
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type AuthedHandler func(http.ResponseWriter, *http.Request, *User)

func (c *Config) middlewareAuth(authFunc AuthedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		id, err := auth.AuthorizeJWT(r.Header, c.jwtSecret)
		if err != nil {
			if !errors.Is(err, jwt.ErrTokenExpired) {
				respondWithJSON(w, http.StatusUnauthorized, "invalid jwt token")
				return
			}
			if err := c.authorizeRefreshToken(ctx, r.Header, id); err != nil {
				respondWithJSON(w, http.StatusUnauthorized, "invalid token")
				return
			}
			jwtToken, err := auth.GenerateJWT(c.jwtSecret, id)
			if err != nil {
				respondWithJSON(w, http.StatusInternalServerError, "internal error")
				return
			}
			r.Header.Set("Authorization", auth.BearerJWT(jwtToken))
		}
		user, err := c.GetUser(ctx, id)
		if err != nil {
			respondWithJSON(w, http.StatusInternalServerError, "couldn't retrieve user")
			return
		}
		authFunc(w, r, &user)
	}
}

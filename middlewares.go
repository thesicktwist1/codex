package main

import (
	"codex/internal/auth"
	"errors"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

type AuthedHandler func(http.ResponseWriter, *http.Request, *User)

func (c *Config) middlewareAuth(authFunc AuthedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := auth.AuthorizeJWT(r.Header, c.jwtSecret)

		var newJWT string
		if err != nil {
			if !errors.Is(err, jwt.ErrTokenExpired) {
				respondWithJSON(w, http.StatusUnauthorized, "invalid jwt token")
				return
			}
			if err := c.authorizeRefreshToken(r.Context(), r.Header, id); err != nil {
				respondWithJSON(w, http.StatusUnauthorized, "invalid token")
				return
			}
			jwtToken, err := auth.GenerateJWT(c.jwtSecret, id)
			if err != nil {
				respondWithJSON(w, http.StatusInternalServerError, "internal error")
				return
			}
			type response struct {
				Token string `json:"token"`
			}
			respondWithJSON(w, http.StatusAccepted, response{
				Token: jwtToken,
			})
			return
		}
		user, err := HGetDecoded[User](r.Context(), c.redis, UsersTable, id)
		if err != nil {
			respondWithJSON(w, http.StatusInternalServerError, "failed to fetch user")
			return
		}
		authFunc(w, r, &user)
	}
}

package main

import (
	"codex/internal/auth"
	"net/http"
)

type AuthedHandler func(http.ResponseWriter, *http.Request, *User)

func (c *Config) middlewareAuth(authFunc AuthedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := auth.AuthorizeJWT(r.Header, c.jwtSecret)
		if err != nil {
			respondWithJSON(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		user, err := HGetDecoded[*User](r.Context(), c.redis, UsersTable, id)
		if err != nil {
			respondWithJSON(w, http.StatusInternalServerError, "failed to fetch user")
			return
		}
		user.HashedPassword = nil
		authFunc(w, r, user)
	}
}

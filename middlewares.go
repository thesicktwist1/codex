package main

import (
	"codex/internal/auth"
	"encoding/json"
	"net/http"
)

type AuthedHandler func(http.ResponseWriter, *http.Request, *User)

func (c *Config) middlewareAuth(authFunc AuthedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := auth.JWTAuthorization(r.Header, c.jwtSecret)
		if err != nil {
			id, err := c.refreshTokenAuth(r.Context(), r.Header)
			if err != nil {
				respondWithJSON(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			jwtToken, err := auth.GenerateJWT(c.jwtSecret, id)
			if err != nil {
				respondWithJSON(w, http.StatusInternalServerError, err)
				return
			}
			w.Header().Set("Authorization", jwtToken)
		}
		data, err := c.redis.Get(r.Context(), id).Bytes()
		if err != nil {
			respondWithJSON(w, http.StatusInternalServerError, err)
			return
		}
		var user User
		if err := json.Unmarshal(data, &user); err != nil {
			respondWithJSON(w, http.StatusInternalServerError, err)
			return
		}
		authFunc(w, r, &user)
	}
}

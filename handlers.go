package main

import (
	"codex/internal/auth"
	"encoding/json"
	"net/http"
	"time"
)

const (
	keySep    = "-"
	users     = "USERS"
	libraries = "LIBRARIES"
	books     = "BOOKS"
)

type AuthedHandler func(http.ResponseWriter, *http.Request, *User)

func (c *Config) handlerRegister(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	params := parameters{}
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "malformed payload")
		return
	}
	if err := auth.RegisterValidation(
		params.Username,
		params.Password,
		params.Email,
	); err != nil {
		respondWithJSON(w, http.StatusBadGateway, err)
		return
	}
	if err := c.LookUpKeys(r.Context(), params.Email, params.Username); err != nil {
		respondWithJSON(w, http.StatusUnauthorized, "user already exist")
		return
	}
	key, err := c.NewKey(r.Context(), params.Email, params.Username)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, err)
		return
	}
	hash, err := auth.HashedPassword(params.Password)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, err)
		return
	}
	// TODO: send confirmation email before
	// creating user or something like that
	user, err := json.Marshal(&User{
		ID:             newID(params.Username),
		CreatedAt:      time.Now().String(),
		UpdatedAt:      time.Now().String(),
		HashedPassword: hash,
		Email:          params.Email,
		Username:       params.Username,
	})
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, err)
		return
	}
	if err := c.redis.Set(r.Context(), key, user, 0).Err(); err != nil {
		respondWithJSON(w, http.StatusInternalServerError, err)
		return
	}
}

func (c *Config) handlerLogin(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Key      string `json:"key"`
		Password string `json:"password"`
	}
	params := parameters{}

	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "malformed payload")
		return
	}
	mainKey, err := c.redis.Get(r.Context(), users).Result()
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, err)
		return
	}
	data, err := c.redis.Get(r.Context(), mainKey).Bytes()
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, err)
		return
	}
	user := User{}
	if err := json.Unmarshal(data, &user); err != nil {
		respondWithJSON(w, http.StatusInternalServerError, err)
		return
	}
	if err := auth.PWValidation(user.HashedPassword, params.Password); err != nil {
		respondWithJSON(w, http.StatusUnauthorized, err)
		return
	}
}

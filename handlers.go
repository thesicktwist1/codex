package main

import (
	"codex/internal/auth"
	"encoding/json"
	"net/http"
	"time"
)

const (
	keySep    = "-"
	user      = "USER"
	libraries = "LIBRARIES"
	books     = "BOOKS"
)

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
	createdAt := time.Now().String()
	updatedAt := time.Now().String()

	user, err := json.Marshal(&User{
		CreatedAt:      createdAt,
		UpdatedAt:      updatedAt,
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
	respondWithJSON(w, http.StatusCreated, User{
		Username:  params.Username,
		Email:     params.Email,
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
	})
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
	id, err := c.redis.Get(r.Context(), EncodeToString([]string{params.Key})).Result()
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, err)
		return
	}
	data, err := c.redis.Get(r.Context(), id).Bytes()
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
	if err := c.revokeRefreshToken(r.Context(), id); err != nil {
		respondWithJSON(w, http.StatusInternalServerError, err)
		return
	}
	refreshToken, err := c.newRefreshToken(r.Context(), id)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, err)
		return
	}
	jwtToken, err := auth.GenerateJWT(c.jwtSecret, id)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, err)
		return
	}
	type response struct {
		User
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}
	respondWithJSON(w, http.StatusAccepted, response{
		User: User{
			Username: user.Username,
			Email:    user.Email,
		},
		RefreshToken: refreshToken,
		Token:        jwtToken,
	})
}

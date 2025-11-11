package main

import (
	"codex/internal/auth"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

func (c *Config) handlerRegisterUser(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	var (
		params parameters
		err    error
	)
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "malformed payload")
		return
	}
	if err := auth.RegisterValidation(
		params.Username,
		params.Password,
		params.Email,
	); err != nil {
		respondWithJSON(w, http.StatusBadRequest, err)
		return
	}
	if err := c.LookUpKeys(r.Context(), params.Email, params.Username); err != nil {
		respondWithJSON(w, http.StatusUnauthorized, "user already exist")
		return
	}
	id, err := c.NewUserKeys(r.Context(), params.Email, params.Username)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "couldn't generate keys")
		return
	}
	hash, err := auth.HashedPassword(params.Password)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	// TODO: send confirmation email before
	// creating user or something like that
	createdAt := time.Now().String()
	updatedAt := time.Now().String()

	user, err := json.Marshal(User{
		CreatedAt:      createdAt,
		UpdatedAt:      updatedAt,
		HashedPassword: hash,
		Email:          params.Email,
		Username:       params.Username,
	})
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := c.redis.HSet(r.Context(), HUsers, map[string]any{
		id: user,
	}).Err(); err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	respondWithJSON(w, http.StatusCreated, User{
		Username:  params.Username,
		Email:     params.Email,
		ID:        id,
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
	if err := auth.IsValidKey(params.Key); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid key")
		return
	}
	id, err := c.redis.HGet(r.Context(), HKeys,
		EncodeToString([]string{params.Key})).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			respondWithJSON(w, http.StatusNoContent, "user doesn't exist")
		} else {
			respondWithJSON(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	user, err := c.GetUser(r.Context(), id)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "couldn't retrieve user")
		return
	}
	if err := bcrypt.CompareHashAndPassword(user.HashedPassword, []byte(params.Password)); err != nil {
		respondWithJSON(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	refreshToken, err := c.redis.HGet(r.Context(), HToken, id).Result()
	if err != nil {
		refreshToken, err = c.newRefreshToken(r.Context(), id)
		if err != nil {
			respondWithJSON(w, http.StatusInternalServerError, "internal error")
			return
		}
	}
	jwtToken, err := auth.GenerateJWT(c.jwtSecret, id)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "error generating token")
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
			ID:       user.ID,
		},
		RefreshToken: refreshToken,
		Token:        jwtToken,
	})
}

func (c *Config) handlerDelete(w http.ResponseWriter, r *http.Request, user *User) {
	type parameters struct {
		Password string `json:"password"`
	}
	params := parameters{}
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "malformed payload")
		return
	}
	if err := auth.IsValidPassword(params.Password); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid input")
		return
	}
	if err := bcrypt.CompareHashAndPassword(user.HashedPassword, []byte(params.Password)); err != nil {
		respondWithJSON(w, http.StatusUnauthorized, "password doesn't match")
		return
	}
	if err := c.DeleteUser(r.Context(), user); err != nil {
		respondWithJSON(w, http.StatusInternalServerError, err)
		return
	}
	emptyResponse(w)
}

func (c *Config) handlerRevokeToken(w http.ResponseWriter, r *http.Request, user *User) {
	token, err := auth.GenerateRefreshToken()
	if err != nil {
		respondWithJSON(w, http.StatusUnauthorized, "invalid token")
		return
	}
	storedToken, err := c.redis.HGet(r.Context(), HToken, user.ID).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			respondWithJSON(w, http.StatusBadRequest, "token doesn't exist")
		} else {
			respondWithJSON(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	if !auth.IsValidRefreshToken(token, storedToken, c.hmacSecret) {
		respondWithJSON(w, http.StatusUnauthorized, "token doesn't match")
		return
	}
	if err := c.redis.HDel(r.Context(), HToken, user.ID); err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	emptyResponse(w)
}

func (c *Config) handlerGetUser(w http.ResponseWriter, r *http.Request, user *User) {
	respondWithJSON(w, http.StatusAccepted, User{
		Username:  user.Username,
		ID:        user.ID,
		Email:     user.Email,
		UpdatedAt: user.UpdatedAt,
		CreatedAt: user.CreatedAt,
	})
}

func (c *Config) handlerUpdateUser(w http.ResponseWriter, r *http.Request, user *User) {
	type parameters struct {
		Password    string `json:"password"`
		NewPassword string `json:"new_password"`
	}
	params := parameters{}
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if err := bcrypt.CompareHashAndPassword(
		user.HashedPassword,
		[]byte(params.Password),
	); err != nil {
		respondWithJSON(w, http.StatusUnauthorized, "invalid password")
		return
	}
	if err := auth.IsValidPassword(params.NewPassword); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid input")
		return
	}
	newPasswordHash, err := auth.HashedPassword(params.NewPassword)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	newUser, err := json.Marshal(User{
		ID:             user.ID,
		Email:          user.Email,
		CreatedAt:      user.CreatedAt,
		UpdatedAt:      time.Now().String(),
		HashedPassword: newPasswordHash,
	})
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := c.redis.HSet(r.Context(), HUsers, user.ID, newUser).Err(); err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	respondWithJSON(w, http.StatusAccepted, User{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		UpdatedAt: time.Now().String(),
		CreatedAt: user.CreatedAt,
	})
}

func (c *Config) handlerRegisterLibrary(w http.ResponseWriter, r *http.Request, user *User) {
	type parameters struct {
		Title   string `json:"title"`
		Private bool   `json:"private"`
	}
	var params parameters
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if err := auth.IsValidTitle(params.Title); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid input")
		return
	}
}

func (c *Config) handlerReadiness(w http.ResponseWriter, r *http.Request) {
	respondWithJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

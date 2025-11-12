package main

import (
	"codex/internal/auth"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
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
	if err := c.redis.HSet(r.Context(), UsersTable, map[string]any{
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
	id, err := c.redis.HGet(r.Context(), KeysTable,
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
	refreshToken, err := c.redis.HGet(r.Context(), TokensTable, id).Result()
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

func (c *Config) handlerDeleteUser(w http.ResponseWriter, r *http.Request, user *User) {
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
	storedToken, err := c.redis.HGet(r.Context(), TokensTable, user.ID).Result()
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
	if err := c.redis.HDel(r.Context(), TokensTable, user.ID); err != nil {
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
	if err := c.redis.HSet(r.Context(), UsersTable, user.ID, newUser).Err(); err != nil {
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

func (c *Config) handlerCreateLibrary(w http.ResponseWriter, r *http.Request, user *User) {
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
	lib, err := c.CreateLibrary(r.Context(), params.Private, params.Title, user.ID)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	respondWithJSON(w, http.StatusCreated, lib)
}

func (c *Config) handlerGetUsersLibraries(w http.ResponseWriter, r *http.Request, user *User) {
	libs, err := c.GetUsersLibraries(r.Context(), user)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "couldn't retrieve libraries")
		return
	}
	respondWithJSON(w, http.StatusAccepted, libs)
}

func (c *Config) handlerGetLibrary(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	owner, private, err := parsedLibraryID(id)
	if err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid url parameter")
		return
	}
	userId, err := auth.AuthorizeJWT(r.Header, c.jwtSecret)
	if err != nil && private {
		respondWithJSON(w, http.StatusUnauthorized, "couldn't retrieve library")
		return
	}
	if private && userId != owner {
		respondWithJSON(w, http.StatusUnauthorized, "no access")
		return
	}
	data, err := c.redis.HGet(r.Context(), LibsTable, id).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			respondWithJSON(w, http.StatusNoContent, "unknown id")
		} else {
			respondWithJSON(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	var lib Library
	if err := json.Unmarshal(data, &lib); err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	var partialContent bool
	trackedList := make([]Tracked, len(lib.TrackerIDs))
	for i, id := range lib.TrackerIDs {
		tracker, err := c.GetBookTracker(r.Context(), id)
		if err != nil {
			if !errors.Is(err, redis.Nil) {
				respondWithJSON(w, http.StatusInternalServerError, "internal error")
				return
			}
			slog.Error("error getting tracker :", "error", err)
			partialContent = true
		} else {
			trackedList[i] = tracker
		}
	}
	type response struct {
		ID        string
		Owner     string
		Title     string
		CreatedAt string
		UpdatedAt string
		Tracked   []Tracked
		Private   bool
	}
	status := http.StatusAccepted
	if partialContent {
		status = http.StatusPartialContent
	}
	respondWithJSON(w, status, response{
		ID:        lib.ID,
		Owner:     lib.Owner,
		Title:     lib.Title,
		CreatedAt: lib.CreatedAt,
		UpdatedAt: lib.UpdatedAt,
		Tracked:   trackedList,
		Private:   lib.Private,
	})
}

func (c *Config) handlerDeleteLibrary(w http.ResponseWriter, r *http.Request, user *User) {
	id := chi.URLParam(r, "id")
	owner, _, err := parsedLibraryID(id)
	if err != nil {
		respondWithJSON(w, http.StatusBadRequest, "malformed id")
		return
	}
	if owner != user.ID {
		respondWithJSON(w, http.StatusUnauthorized, "no access")
		return
	}
	if err := c.redis.HDel(r.Context(), LibsTable, id).Err(); err != nil {
		if errors.Is(err, redis.Nil) {
			respondWithJSON(w, http.StatusNotFound, "couldn't retrieve library")
		} else {
			respondWithJSON(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	emptyResponse(w)
}

func (c *Config) handlerReadiness(w http.ResponseWriter, r *http.Request) {
	respondWithJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

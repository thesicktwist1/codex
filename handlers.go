package main

import (
	"codex/internal/auth"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
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
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
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
	if err := c.LookUpKeys(ctx, params.Email, params.Username); err != nil {
		respondWithJSON(w, http.StatusUnauthorized, "user already exist")
		return
	}
	id, err := c.NewUserKeys(ctx, params.Email, params.Username)
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

	if err := c.HSetEncoded(ctx, UsersTable, id, User{
		CreatedAt:      createdAt,
		UpdatedAt:      updatedAt,
		HashedPassword: hash,
		Email:          params.Email,
		Username:       params.Username,
	}); err != nil {
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
	var params parameters

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "malformed payload")
		return
	}
	if err := auth.IsValidKey(params.Key); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid key")
		return
	}
	id, err := c.redis.HGet(ctx, KeysTable,
		EncodeToString([]string{params.Key})).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			respondWithJSON(w, http.StatusNoContent, "user doesn't exist")
		} else {
			respondWithJSON(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	user, err := HGetDecoded[User](ctx, c.redis, UsersTable, id)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := bcrypt.CompareHashAndPassword(user.HashedPassword, []byte(params.Password)); err != nil {
		respondWithJSON(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	refreshToken, err := c.redis.HGet(ctx, TokensTable, id).Result()
	if err != nil {
		refreshToken, err = c.updateRefreshToken(ctx, id)
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
	var params parameters
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
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
	if err := c.DeleteUser(ctx, user); err != nil {
		respondWithJSON(w, http.StatusInternalServerError, err)
		return
	}
	emptyResponse(w)
}

func (c *Config) handlerRevokeToken(w http.ResponseWriter, r *http.Request, user *User) {
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	token, err := auth.GenerateRefreshToken()
	if err != nil {
		respondWithJSON(w, http.StatusUnauthorized, "invalid token")
		return
	}
	storedToken, err := c.redis.HGet(ctx, TokensTable, user.ID).Result()
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
	if err := c.redis.HDel(ctx, TokensTable, user.ID); err != nil {
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
	var params parameters
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
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
	if err := c.HSetEncoded(ctx, UsersTable, user.ID, User{
		ID:             user.ID,
		Email:          user.Email,
		CreatedAt:      user.CreatedAt,
		UpdatedAt:      time.Now().String(),
		HashedPassword: newPasswordHash,
	}); err != nil {
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
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	var params parameters
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if err := auth.IsValidTitle(params.Title); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid input")
		return
	}
	lib, err := c.CreateLibrary(ctx, params.Private, params.Title, user.ID)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	respondWithJSON(w, http.StatusCreated, lib)
}

func (c *Config) handlerGetUsersLibraries(w http.ResponseWriter, r *http.Request, user *User) {
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	keys, err := c.HScanKeys(ctx, LibsTable, user.ID, 0)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	libs := make([]Library, len(keys))
	for i, key := range keys {
		lib, err := HGetDecoded[Library](ctx, c.redis, LibsTable, key)
		if err != nil {
			respondWithJSON(w, http.StatusInternalServerError, "internal error")
			return
		}
		libs[i] = lib
	}
	respondWithJSON(w, http.StatusAccepted, libs)
}

func (c *Config) handlerGetLibrary(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	id := chi.URLParam(r, "id")
	if err := validateURLParam(id); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid url parameter")
		return
	}
	owner, private, err := parsedId(id)
	if err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid url parameter")
		return
	}
	userId, _ := auth.AuthorizeJWT(r.Header, c.jwtSecret)
	if private && userId != owner {
		respondWithJSON(w, http.StatusUnauthorized, "couldn't retrieve library")
		return
	}
	lib, err := HGetDecoded[Library](ctx, c.redis, LibsTable, id)
	if err != nil {
		if errors.Is(err, redis.Nil) {
			respondWithJSON(w, http.StatusNoContent, "unknown id")
		} else {
			respondWithJSON(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	status := http.StatusOK
	books := make([]Book, len(lib.BookIDs))
	for i, id := range lib.BookIDs {
		book, err := HGetDecoded[Book](ctx, c.redis, BooksTable, id)
		if err != nil {
			if !errors.Is(err, redis.Nil) {
				respondWithJSON(w, http.StatusInternalServerError, "internal error")
				return
			}
			slog.Error("key doesn't exist", "error", err)
			status = http.StatusPartialContent
		} else {
			books[i] = book
		}
	}
	type response struct {
		ID        string
		Owner     string
		Title     string
		CreatedAt string
		UpdatedAt string
		Books     []Book
		Private   bool
	}
	respondWithJSON(w, status, response{
		ID:        lib.ID,
		Owner:     lib.Owner,
		Title:     lib.Title,
		CreatedAt: lib.CreatedAt,
		UpdatedAt: lib.UpdatedAt,
		Books:     books,
		Private:   lib.Private,
	})
}

func (c *Config) handlerDeleteLibrary(w http.ResponseWriter, r *http.Request, user *User) {
	id := chi.URLParam(r, "id")
	if err := validateURLParam(id); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid url parameter")
		return
	}
	owner, _, err := parsedId(id)
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

func (c *Config) handlerGetBooks(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	var (
		page, limit int
		err         error
	)
	page, err = parseURLQueryInt(r.URL.Query().Get("page"))
	if err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid page query")
		return
	}
	limit, err = parseURLQueryInt(r.URL.Query().Get("limit"))
	if err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid limit query")
		return
	}
	offset := (page - 1) * limit
	keys, err := GetDecoded[[]string](ctx, c.redis, BookKeys)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	books := make([]Book, pageLimit)
	status := http.StatusAccepted
	for i, key := range keys[offset : offset+limit] {
		book, err := HGetDecoded[Book](ctx, c.redis, BooksTable, key)
		if err != nil {
			if errors.Is(err, redis.Nil) {
				slog.Error("error key doesn't exist", "err", err)
				status = http.StatusPartialContent
				continue
			}
			respondWithJSON(w, http.StatusInternalServerError, "internal error")
			return
		}
		books[i] = book
	}
	respondWithJSON(w, status, books)
}

func (c *Config) handlerGetBookById(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	id := chi.URLParam(r, "id")
	if err := validateURLParam(id); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid url parameter")
		return
	}
	book, err := HGetDecoded[Book](ctx, c.redis, BooksTable, id)
	if err != nil {
		if errors.Is(err, redis.Nil) {
			respondWithJSON(w, http.StatusNoContent, "id doesn't exist")
		} else {
			respondWithJSON(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	respondWithJSON(w, http.StatusAccepted, book)
}

func (c *Config) handlerGetReviewById(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	id := chi.URLParam(r, "id")
	if err := validateURLParam(id); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid url parameter")
		return
	}
	owner, private, err := parsedId(id)
	if err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid id")
		return
	}
	userId, _ := auth.AuthorizeJWT(r.Header, c.jwtSecret)
	if private && userId != owner {
		respondWithJSON(w, http.StatusUnauthorized, "")
	}
	review, err := HGetDecoded[Review](ctx, c.redis, ReviewsTable, id)
	if err != nil {
		if errors.Is(err, redis.Nil) {
			respondWithJSON(w, http.StatusNoContent, "review doesn't exist")
		} else {
			respondWithJSON(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	respondWithJSON(w, http.StatusOK, review)
}

func (c *Config) handlerUpdateReview(w http.ResponseWriter, r *http.Request, user *User) {
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	bookId := chi.URLParam(r, "bookId")
	if err := validateURLParam(bookId); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid url parameter")
		return
	}
	type parameters struct {
		Description string `json:"description"`
		Status      uint32 `json:"status"`
		Note        int    `json:"note"`
		CurrentPage int    `json:"current_page"`
		Private     bool   `json:"private"`
	}
	var params parameters
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	match := formatId(user.ID, bookId)
	keys, err := c.HScanKeys(ctx, ReviewsTable, match, 0)
	if err != nil || len(keys) > 1 {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	if len(keys) == 0 {
		respondWithJSON(w, http.StatusNotFound, "couldn't retrieve id")
		return
	}
	review, err := HGetDecoded[Review](ctx, c.redis, ReviewsTable, keys[0])
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	updatedAt := time.Now().String()

	newReview := Review{
		BookID:      review.BookID,
		UserID:      review.UserID,
		Description: params.Description,
		UpdatedAt:   updatedAt,
		CreatedAt:   review.CreatedAt,
		CurrentPage: params.CurrentPage,
		Private:     params.Private,
		Status:      Status(params.Status),
		Note:        params.Note,
	}
	if err := c.HSetEncoded(ctx, ReviewsTable, keys[0], review); err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	respondWithJSON(w, http.StatusAccepted, newReview)

}

func (c *Config) handlerCreateReview(w http.ResponseWriter, r *http.Request, user *User) {
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	bookId := chi.URLParam(r, "bookId")
	if err := validateURLParam(bookId); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid url parameter")
		return
	}
	exist, err := c.redis.HExists(ctx, BooksTable, bookId).Result()
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !exist {
		respondWithJSON(w, http.StatusNotFound, "invalid book id")
		return
	}
	match := formatId(user.ID, bookId)
	keys, err := c.HScanKeys(ctx, ReviewsTable, match, 0)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	if len(keys) != 0 {
		respondWithJSON(w, http.StatusConflict, "id already exist")
		return
	}
	type parameters struct {
		Description string `json:"description"`
		Status      uint32 `json:"status"`
		Note        int    `json:"note"`
		CurrentPage int    `json:"current_page"`
		Private     bool   `json:"private"`
	}
	var params parameters
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid payload")
		return
	}

	var (
		reviewId  = strings.Join([]string{match, boolToString(params.Private)}, Sep)
		createdAt = time.Now().String()
	)
	review := Review{
		BookID:      bookId,
		UserID:      user.ID,
		CreatedAt:   createdAt,
		UpdatedAt:   createdAt,
		Description: params.Description,
		Status:      Status(params.Status),
		CurrentPage: params.CurrentPage,
		Note:        params.Note,
		Private:     params.Private,
	}
	if err := c.HSetEncoded(ctx, ReviewsTable, reviewId, review); err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := c.HKeysAppend(ctx, ReviewKeys, bookId, reviewId); err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	respondWithJSON(w, http.StatusCreated, review)
}

func (c *Config) handlerDeleteReview(w http.ResponseWriter, r *http.Request, user *User) {
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	bookId := chi.URLParam(r, "bookId")
	if err := validateURLParam(bookId); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid url parameter")
		return
	}
	match := formatId(user.ID, bookId)
	keys, err := c.HScanKeys(ctx, ReviewsTable, match, 0)
	if err != nil || len(keys) > 1 {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	if len(keys) < 1 {
		respondWithJSON(w, http.StatusNotFound, "couldn't retrieve review id")
		return
	}
	if err := c.redis.HDel(ctx, ReviewsTable, keys[0]).Err(); err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := c.HKeysDelete(ctx, ReviewKeys, bookId, keys[0]); err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	emptyResponse(w)
}

func (c *Config) handlerGetReviewsByBookId(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	bookId := chi.URLParam(r, "id")
	if err := validateURLParam(bookId); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid url parameter")
		return
	}
	page, err := parseURLQueryInt(r.URL.Query().Get("page"))
	if err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid url query")
		return
	}
	limit, err := parseURLQueryInt(r.URL.Query().Get("limit"))
	if err != nil {
		limit = pageLimit
	}
	offset := (page - 1) * limit
	keys, err := HGetDecoded[[]string](ctx, c.redis, ReviewKeys, bookId)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	reviews := make([]Review, limit)
	status := http.StatusAccepted
	for i, key := range keys[offset : offset+limit] {
		review, err := HGetDecoded[Review](ctx, c.redis, ReviewsTable, key)
		if err != nil {
			if errors.Is(err, redis.Nil) {
				slog.Error("error key doesn't exist", "err", err)
				status = http.StatusPartialContent
				continue
			}
			respondWithJSON(w, http.StatusInternalServerError, "internal error")
		}
		reviews[i] = review
	}
	respondWithJSON(w, status, reviews)
}

func (c *Config) handlerGetTracked(w http.ResponseWriter, r *http.Request, user *User) {
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	keys, err := c.HScanKeys(ctx, ReviewsTable, user.ID, 0)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	trackers := make([]Tracker, len(keys))
	for i, key := range keys {
		review, err := HGetDecoded[Review](ctx, c.redis, ReviewsTable, key)
		if err != nil {
			respondWithJSON(w, http.StatusInternalServerError, "internal error")
			return
		}
		book, err := HGetDecoded[Book](ctx, c.redis, BooksTable, review.BookID)
		if err != nil {
			respondWithJSON(w, http.StatusInternalServerError, "internal error")
			return
		}
		trackers[i] = Tracker{Review: review, Book: book}
	}
}

func (c *Config) handlerFetchBookById(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	id := chi.URLParam(r, "id")
	if err := validateURLParam(id); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid url parameter")
		return
	}
	book, err := HGetDecoded[Book](ctx, c.redis, BooksTable, id)
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			respondWithJSON(w, http.StatusInternalServerError, "internal error")
			return
		}
		url := formatFetchURLById(id)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			respondWithJSON(w, http.StatusInternalServerError, "internal error")
			return
		}
		resp, err := c.client.Do(req)
		if err != nil {
			respondWithJSON(w, http.StatusInternalServerError, "internal error")
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			respondWithJSON(w, resp.StatusCode, "external api error")
			return
		}
		if err := json.NewDecoder(resp.Body).Decode(&book); err != nil {
			respondWithJSON(w, http.StatusInternalServerError, "internal error")
			return
		}
		if err := c.CreateBook(ctx, &book); err != nil {
			slog.Error("error creating book : ", "error", err)
		}
	}
	respondWithJSON(w, http.StatusCreated, book)
}

func (c *Config) handlerFetchBookListQueries(w http.ResponseWriter, r *http.Request) {
	_ = r.URL.Query()

}

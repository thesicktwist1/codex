package main

import (
	"codex/internal/auth"
	"codex/internal/identifier"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
		respondWithJSON(w, http.StatusConflict, "user already exist")
		return
	}
	id, err := c.GenerateUserKeys(ctx, params.Email, params.Username)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "couldn't generate keys")
		return
	}
	hash, err := auth.HashedPassword(params.Password)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}

	createdAt := time.Now().String()
	updatedAt := time.Now().String()

	if ok, err := c.HSetEncodedNX(ctx, UsersTable, id, User{
		CreatedAt:      createdAt,
		UpdatedAt:      updatedAt,
		HashedPassword: hash,
		Email:          params.Email,
		Username:       params.Username,
		ID:             id,
	}); err != nil || !ok {
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
			respondWithJSON(w, http.StatusNoContent, "couldn't find user")
		} else {
			respondWithJSON(w, http.StatusInternalServerError, "internal error")
		}
		return
	}

	user, err := HGetDecoded[User](r.Context(), c.redis, UsersTable, id)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := bcrypt.CompareHashAndPassword(user.HashedPassword, []byte(params.Password)); err != nil {
		respondWithJSON(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	refreshToken, err := auth.GenerateRefreshToken()
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	hashedToken := auth.HashRefreshToken(refreshToken)
	if err := c.redis.SetEx(
		r.Context(),
		hashedToken,
		user.ID,
		auth.TokenExpirationTime,
	).Err(); err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}

	jwtToken, err := auth.GenerateJWT(c.jwtSecret, user.ID)
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
			ID:       id,
		},
		RefreshToken: refreshToken,
		Token:        jwtToken,
	})
}

func (c *Config) handlerRefresh(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetRefreshToken(r.Header)
	if err != nil {
		respondWithJSON(w, http.StatusUnauthorized, "no token included")
		return
	}
	hash := auth.HashRefreshToken(token)
	userId, err := c.redis.GetDel(r.Context(), hash).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			respondWithJSON(w, http.StatusUnauthorized, "invalid credentials")
		} else {
			respondWithJSON(w, http.StatusInternalServerError, "internal error")
		}
		return
	}

	refreshToken, err := auth.GenerateRefreshToken()
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}

	hash = auth.HashRefreshToken(refreshToken)
	if err := c.redis.SetEx(
		r.Context(),
		hash,
		userId,
		auth.TokenExpirationTime,
	).Err(); err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}

	jwtToken, err := auth.GenerateJWT(c.jwtSecret, userId)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}

	respondWithJSON(w, http.StatusAccepted, map[string]string{
		"refresh_token": refreshToken,
		"token":         jwtToken,
	})
}

func (c *Config) handlerDeleteUser(w http.ResponseWriter, r *http.Request, user *User) {
	type parameters struct {
		Password string `json:"password"`
	}
	var params parameters
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "malformed payload")
		return
	}
	if err := auth.IsValidPassword(params.Password); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid input")
		return
	}
	user, err := HGetDecoded[*User](r.Context(), c.redis, UsersTable, user.ID)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
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
	token, err := auth.GetRefreshToken(r.Header)
	if err != nil {
		respondWithJSON(w, http.StatusNoContent, "invalid credentials")
		return
	}
	hash := auth.HashRefreshToken(token)
	if _, err := c.redis.Del(r.Context(), hash).Result(); err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	emptyResponse(w)
}

func (c *Config) handlerUpdateUser(w http.ResponseWriter, r *http.Request, user *User) {
	type parameters struct {
		Password    string `json:"password"`
		NewPassword string `json:"new_password"`
	}
	var params parameters
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if err := auth.IsValidPassword(params.NewPassword); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid input")
		return
	}
	if err := auth.IsValidPassword(params.Password); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid input")
		return
	}
	user, err := HGetDecoded[*User](r.Context(), c.redis, UsersTable, user.ID)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "couldn't retrieve user")
		return
	}
	if err := bcrypt.CompareHashAndPassword(
		user.HashedPassword, []byte(params.Password)); err != nil {
		respondWithJSON(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	newPasswordHash, err := auth.HashedPassword(params.NewPassword)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := c.HSetEncoded(r.Context(), UsersTable, user.ID, User{
		ID:             user.ID,
		Email:          user.Email,
		Username:       user.Username,
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
	var params parameters
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if err := auth.IsValidTitle(params.Title); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid input")
		return
	}

	createdAt := time.Now().String()
	libraryId := EncodeToString([]string{params.Title, createdAt})

	id, err := identifier.Format(user.ID, libraryId, params.Private)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	lib := Library{
		ID:        id,
		Owner:     user.ID,
		Title:     params.Title,
		CreatedAt: createdAt,
		UpdatedAt: createdAt,
		BooksID:   make([]string, 0),
		Private:   params.Private,
	}
	if ok, err := c.HSetEncodedNX(r.Context(), LibraryTable, lib.ID, lib); err != nil || !ok {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	respondWithJSON(w, http.StatusCreated, lib)
}

func (c *Config) handlerGetUsersLibraries(w http.ResponseWriter, r *http.Request, user *User) {
	keys, err := c.HScanAllKeys(r.Context(), LibraryTable, user.ID)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error "+err.Error())
		return
	}
	libs := make([]*Library, len(keys))
	for i, key := range keys {
		lib, err := HGetDecoded[*Library](r.Context(), c.redis, LibraryTable, key)
		if err != nil {
			respondWithJSON(w, http.StatusInternalServerError, "internal error 2")
			return
		}
		libs[i] = lib
	}
	respondWithJSON(w, http.StatusAccepted, libs)
}

func (c *Config) handlerGetLibrary(w http.ResponseWriter, r *http.Request) {
	libraryID := chi.URLParam(r, "libraryID")
	if err := validateURLParams(libraryID); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid url parameter 1")
		return
	}
	id, err := identifier.New(libraryID)
	if err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid id")
		return
	}
	userId, _ := auth.AuthorizeJWT(r.Header, c.jwtSecret)
	if id.Private && id.Owner != userId {
		respondWithJSON(w, http.StatusUnauthorized, "couldn't retrieve library")
		return
	}
	lib, err := HGetDecoded[Library](r.Context(), c.redis, LibraryTable, id.String())
	if err != nil {
		if errors.Is(err, redis.Nil) {
			respondWithJSON(w, http.StatusNoContent, "unknown id")
		} else {
			respondWithJSON(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	books, err := GetBooks(r.Context(), c.redis, lib.BooksID)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
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
	respondWithJSON(w, http.StatusOK, response{
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
	libraryID := chi.URLParam(r, "libraryID")
	if err := validateURLParams(libraryID); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid url parameter")
		return
	}
	id, err := identifier.New(libraryID)
	if err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid id")
		return
	}
	if id.Owner != user.ID {
		respondWithJSON(w, http.StatusUnauthorized, "no access")
		return
	}
	if err := c.redis.HDel(r.Context(), LibraryTable, libraryID).Err(); err != nil {
		if errors.Is(err, redis.Nil) {
			respondWithJSON(w, http.StatusNotFound, "couldn't retrieve library")
		} else {
			respondWithJSON(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	emptyResponse(w)
}

func (c *Config) handlerDeleteLibraryBook(w http.ResponseWriter, r *http.Request, user *User) {
	libraryID := chi.URLParam(r, "libraryID")
	bookIdx := chi.URLParam(r, "bookIdx")
	if err := validateURLParams(libraryID, bookIdx); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid parameters")
		return
	}
	id, err := identifier.New(libraryID)
	if err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid id")
		return
	}
	if id.Owner != user.ID {
		respondWithJSON(w, http.StatusUnauthorized, "invalid credentialss")
		return
	}
	library, err := HGetDecoded[*Library](r.Context(), c.redis, LibraryTable, libraryID)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "couldn't retrieve library")
		return
	}
	index, err := validateIndex(bookIdx, len(library.BooksID))
	if err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid index parameter ")
		return
	}
	library.Delete(index)
	if err := c.HSetEncoded(r.Context(), LibraryTable, library.ID, library); err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	books, err := GetBooks(r.Context(), c.redis, library.BooksID)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
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
	respondWithJSON(w, http.StatusAccepted, response{
		ID:        library.ID,
		Owner:     library.Owner,
		Title:     library.Title,
		CreatedAt: library.CreatedAt,
		UpdatedAt: library.UpdatedAt,
		Books:     books,
		Private:   library.Private,
	})
}

func (c *Config) handlerUpdateLibraryBooks(w http.ResponseWriter, r *http.Request, user *User) {
	bookID := chi.URLParam(r, "bookID")
	libraryID := chi.URLParam(r, "libraryID")

	library, err := HGetDecoded[Library](r.Context(), c.redis, LibraryTable, libraryID)
	if err != nil {
		if errors.Is(err, redis.Nil) {
			respondWithJSON(w, http.StatusNotFound, "couldn't retrieve library")
		} else {
			respondWithJSON(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	exist, err := c.redis.HExists(r.Context(), BooksTable, bookID).Result()
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !exist {
		respondWithJSON(w, http.StatusNotFound, "couldn't retrieve given book id")
		return
	}
	library.Append(bookID)
	if err := c.HSetEncoded(r.Context(), LibraryTable, library.ID, library); err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	books, err := GetBooks(r.Context(), c.redis, library.BooksID)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
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
	respondWithJSON(w, http.StatusOK, response{
		ID:        library.ID,
		Owner:     library.Owner,
		Title:     library.Title,
		CreatedAt: library.CreatedAt,
		UpdatedAt: library.UpdatedAt,
		Books:     books,
		Private:   library.Private,
	})
}

func (c *Config) handlerCreateBook(w http.ResponseWriter, r *http.Request) {
	var book Book
	if err := json.NewDecoder(r.Body).Decode(&book); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid payload")
		return
	}
	// TODO: sanitize the books fields to ensure storage safety
	exist, err := c.HSetEncodedNX(r.Context(), BooksTable, book.ID, book)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error :"+fmt.Sprintf("%s", err))
		return
	}
	if !exist {
		respondWithJSON(w, http.StatusConflict, "book already exist")
		return
	}
	respondWithJSON(w, http.StatusCreated, book)
}

func (c *Config) handlerGetBooks(w http.ResponseWriter, r *http.Request) {
	var (
		page, limit int
		err         error
	)
	page, err = parseURLQueryInt(r.URL.Query().Get("page"))
	if err != nil || page == 0 {
		page = 1
	}
	limit, err = parseURLQueryInt(r.URL.Query().Get("limit"))
	if err != nil || limit == 0 {
		limit = pageLimit
	}
	offset := (page - 1) * limit
	keys, err := c.redis.HKeys(r.Context(), BooksTable).Result()
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	if offset >= len(keys) {
		offset = 0
		limit = len(keys)
	} else if limit >= len(keys) {
		limit = len(keys)
	}
	books := make([]*Book, limit)
	status := http.StatusAccepted
	for i, key := range keys[offset : offset+limit] {
		book, err := HGetDecoded[*Book](r.Context(), c.redis, BooksTable, key)
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
	id := chi.URLParam(r, "bookID")
	if err := validateURLParams(id); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid url parameter")
		return
	}
	book, err := HGetDecoded[Book](r.Context(), c.redis, BooksTable, id)
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
	reviewID := chi.URLParam(r, "reviewID")
	if err := validateURLParams(reviewID); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid url parameter")
		return
	}
	id, err := identifier.New(reviewID)
	if err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid id")
		return
	}
	userId, _ := auth.AuthorizeJWT(r.Header, c.jwtSecret)
	if id.Private && userId != id.Owner {
		respondWithJSON(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	review, err := HGetDecoded[Review](r.Context(), c.redis, ReviewsTable, id.String())
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
	reviewID := chi.URLParam(r, "reviewID")
	if err := validateURLParams(reviewID); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid url parameter")
		return
	}
	id, err := identifier.New(reviewID)
	if err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid id")
		return
	}
	if id.Owner != user.ID {
		respondWithJSON(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	review, err := HGetDecoded[Review](r.Context(), c.redis, ReviewsTable, reviewID)
	if err != nil {
		if errors.Is(err, redis.Nil) {
			respondWithJSON(w, http.StatusNotFound, "no review found")
		} else {
			respondWithJSON(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	var params struct {
		Description string `json:"description"`
		Status      uint32 `json:"status"`
		Rating      int    `json:"rating"`
		CurrentPage int    `json:"current_page"`
		Private     bool   `json:"private"`
	}
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	if id.Private != params.Private {
		if err := c.redis.HDel(r.Context(), ReviewsTable, reviewID).Err(); err != nil {
			respondWithJSON(w, http.StatusInternalServerError, "internal error")
			return
		}
		id.Private = params.Private
	}
	updatedAt := time.Now().String()

	review = Review{
		BookID:      review.BookID,
		UserID:      review.UserID,
		Description: params.Description,
		UpdatedAt:   updatedAt,
		CreatedAt:   review.CreatedAt,
		CurrentPage: params.CurrentPage,
		Private:     params.Private,
		Status:      Status(params.Status),
		Rating:      params.Rating,
	}
	if err := c.HSetEncoded(r.Context(), ReviewsTable, id.String(), review); err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	respondWithJSON(w, http.StatusAccepted, review)
}

func (c *Config) handlerCreateReview(w http.ResponseWriter, r *http.Request, user *User) {
	bookId := chi.URLParam(r, "bookID")
	if err := validateURLParams(bookId); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid url parameter")
		return
	}
	exist, err := c.redis.HExists(r.Context(), BooksTable, bookId).Result()
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !exist {
		respondWithJSON(w, http.StatusNotFound, "invalid book id")
		return
	}
	match := strings.Join([]string{user.ID, bookId}, IDSep)
	keys, err := c.HScanAllKeys(r.Context(), ReviewsTable, match)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	if len(keys) > 0 {
		respondWithJSON(w, http.StatusConflict, "review already exist")
		return
	}
	var params struct {
		Description string `json:"description"`
		Status      int    `json:"status"`
		Rating      int    `json:"rating"`
		CurrentPage int    `json:"current_page"`
		Private     bool   `json:"private"`
	}
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid payload")
		return
	}
	// todo : payload sanitazing
	createdAt := time.Now().String()
	review := &Review{
		BookID:      bookId,
		UserID:      user.ID,
		CreatedAt:   createdAt,
		UpdatedAt:   createdAt,
		Description: params.Description,
		Status:      Status(params.Status),
		CurrentPage: params.CurrentPage,
		Rating:      params.Rating,
		Private:     params.Private,
	}

	if err := c.CreateReview(r.Context(), review); err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}

	respondWithJSON(w, http.StatusCreated, review)
}

func (c *Config) handlerDeleteReview(w http.ResponseWriter, r *http.Request, user *User) {
	reviewID := chi.URLParam(r, "reviewID")
	if err := validateURLParams(reviewID); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid url parameter")
		return
	}
	id, err := identifier.New(reviewID)
	if err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid id")
		return
	}
	if id.Owner != user.ID {
		respondWithJSON(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	n, err := c.redis.HDel(r.Context(), ReviewsTable, reviewID).Result()
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	if n < 1 {
		respondWithJSON(w, http.StatusNotFound, "review not found")
		return
	}
	emptyResponse(w)
}

func (c *Config) handlerGetReviewsByBookId(w http.ResponseWriter, r *http.Request) {
	bookId := chi.URLParam(r, "bookID")
	if err := validateURLParams(bookId); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid url parameter")
		return
	}
	page, err := parseURLQueryInt(r.URL.Query().Get("page"))
	if err != nil || page == 0 {
		page = 1
	}
	limit, err := parseURLQueryInt(r.URL.Query().Get("limit"))
	if err != nil || limit == 0 {
		limit = pageLimit
	}
	offset := (page - 1) * limit
	match := strings.Join([]string{bookId, "0"}, IDSep)
	keys, err := c.HScanAllKeys(r.Context(), ReviewsTable, match)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	if offset >= len(keys) {
		offset = 0
		limit = len(keys)
	} else if limit >= len(keys) {
		limit = len(keys)
	}
	reviews := make([]*Review, limit)
	status := http.StatusAccepted
	for i, key := range keys[offset : offset+limit] {
		review, err := HGetDecoded[*Review](r.Context(), c.redis, ReviewsTable, key)
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
	keys, err := c.HScanAllKeys(r.Context(), ReviewsTable, user.ID)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	trackers := make([]Tracker, len(keys))
	for i, key := range keys {
		review, err := HGetDecoded[Review](r.Context(), c.redis, ReviewsTable, key)
		if err != nil {
			respondWithJSON(w, http.StatusInternalServerError, "internal error")
			return
		}
		book, err := HGetDecoded[Book](r.Context(), c.redis, BooksTable, review.BookID)
		if err != nil {
			respondWithJSON(w, http.StatusInternalServerError, "internal error")
			return
		}
		trackers[i] = Tracker{Review: review, Book: book}
	}
	respondWithJSON(w, http.StatusAccepted, trackers)
}

func (c *Config) handlerReadiness(w http.ResponseWriter, r *http.Request) {
	respondWithJSON(w, http.StatusOK, map[string]string{"status": "ok"})
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

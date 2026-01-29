package main

import (
	"codex/internal/auth"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
		respondWithJSON(w, http.StatusBadRequest, "invalid payload"+err.Error())
		return
	}
	if err := auth.IsValidTitle(params.Title); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid input"+err.Error())
		return
	}

	createdAt := time.Now().String()
	id := EncodeToString([]string{params.Title, createdAt})

	lib := Library{
		ID:        formatId(user.ID, id),
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
	libs := make([]Library, len(keys))
	for i, key := range keys {
		lib, err := HGetDecoded[Library](r.Context(), c.redis, LibraryTable, key)
		if err != nil {
			respondWithJSON(w, http.StatusInternalServerError, "internal error 2")
			return
		}
		libs[i] = lib
	}
	respondWithJSON(w, http.StatusAccepted, libs)
}

func (c *Config) handlerGetLibrary(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "libraryID")
	if err := validateURLParam(id); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid url parameter 1")
		return
	}
	ownerId, err := parseOwnerID(id)
	if err != nil {
		respondWithJSON(w, http.StatusBadRequest, "couldn't parse library id")
		return
	}
	userId, _ := auth.AuthorizeJWT(r.Header, c.jwtSecret)
	lib, err := HGetDecoded[Library](r.Context(), c.redis, LibraryTable, id)
	if err != nil {
		if errors.Is(err, redis.Nil) {
			respondWithJSON(w, http.StatusNoContent, "unknown id")
		} else {
			respondWithJSON(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	if lib.Private && ownerId != userId {
		respondWithJSON(w, http.StatusUnauthorized, "couldn't retrieve library")
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
	id := chi.URLParam(r, "libraryID")
	if err := validateURLParam(id); err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid url parameter")
		return
	}
	owner, err := parseOwnerID(id)
	if err != nil {
		respondWithJSON(w, http.StatusBadRequest, "malformed id")
		return
	}
	if owner != user.ID {
		respondWithJSON(w, http.StatusUnauthorized, "no access")
		return
	}
	if err := c.redis.HDel(r.Context(), LibraryTable, id).Err(); err != nil {
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
	library, err := HGetDecoded[Library](r.Context(), c.redis, LibraryTable, libraryID)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "couldn't retrieve library")
		return
	}
	idx, err := validateIndex(bookIdx, len(library.BooksID))
	if err != nil {
		respondWithJSON(w, http.StatusBadRequest, "invalid index parameter")
		return
	}
	exist, err := c.redis.HExists(r.Context(), BooksTable, library.BooksID[idx]).Result()
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !exist {
		respondWithJSON(w, http.StatusNotFound, "couldn't retrieve given book id")
		return
	}

	library.BooksID = append(library.BooksID[:idx], library.BooksID[idx+1:]...)

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
	library.BooksID = append(library.BooksID, bookID)

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
	keys, err := GetDecoded[[]string](r.Context(), c.redis, BookKeys)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	books := make([]Book, pageLimit)
	status := http.StatusAccepted
	for i, key := range keys[offset : offset+limit] {
		book, err := HGetDecoded[Book](r.Context(), c.redis, BooksTable, key)
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
	owner, private, err := parseReviewID(id)
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
	keys, err := c.HScanAllKeys(ctx, ReviewsTable, match)
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
	if err := c.redis.HSet(ctx, ReviewsTable, keys[0], review); err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	respondWithJSON(w, http.StatusAccepted, newReview)

}

func (c *Config) handlerCreateReview(w http.ResponseWriter, r *http.Request, user *User) {
	bookId := chi.URLParam(r, "bookId")
	if err := validateURLParam(bookId); err != nil {
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

	reviewId := formatId(user.ID, bookId)
	createdAt := time.Now().String()

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

	exist, err = c.redis.HSetNX(r.Context(), ReviewsTable, reviewId, review).Result()
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := c.HKeysAppend(r.Context(), ReviewKeys, bookId, reviewId); err != nil {
		respondWithJSON(w, http.StatusInternalServerError, "internal error")
		return
	}
	respondWithJSON(w, http.StatusCreated, review)
}

func (c *Config) handlerDeleteReview(w http.ResponseWriter, r *http.Request, user *User) {

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
	keys, err := c.HScanAllKeys(ctx, ReviewsTable, user.ID)
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

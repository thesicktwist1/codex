package main

import (
	"bytes"
	"codex/internal/auth"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

const (
	jwtSecretTest   = "34236121r2311d"
	LibraryTestName = "Title Test 123"
)

func setupUser(config *Config, t *testing.T) []byte {
	body := bytes.NewBuffer([]byte(
		`{
	  "email": "user@example.com",
	  "username": "johnnytest34",
	  "password": "superSecret123"
	    }`))
	r := httptest.NewRequest("POST", "/register", body)
	w := httptest.NewRecorder()

	config.ServeHTTP(w, r)

	require.Equalf(t, http.StatusCreated, w.Code, "%s", w.Body.String())

	body = bytes.NewBuffer([]byte(
		`{
	    "key": "johnnytest34",
		"password": "superSecret123"
		}`))

	r = httptest.NewRequest("POST", "/login", body)
	w = httptest.NewRecorder()

	config.ServeHTTP(w, r)

	require.Equalf(t, http.StatusAccepted, w.Code, "%s", w.Body.String())
	return w.Body.Bytes()
}

func setupUsersLibrary(config *Config, t *testing.T) []byte {
	usersData := setupUser(config, t)

	type response struct {
		RefreshToken string `json:"refresh_token"`
		Token        string `json:"token"`
	}
	var resp response

	err := json.Unmarshal(usersData, &resp)
	require.NoError(t, err)

	data := fmt.Appendf([]byte{},
		`{"title": "%s", "private": false}`, LibraryTestName)
	body := bytes.NewBuffer(data)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/libraries", body)

	r.Header.Set("X-Refresh-Token", resp.RefreshToken)
	r.Header.Set("Authorization", "Bearer "+resp.Token)

	config.ServeHTTP(w, r)

	require.Equalf(t, http.StatusCreated, w.Code, "%s", w.Body.String())

	return w.Body.Bytes()
}

func setupRedis(t *testing.T) *redis.Client {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(mr.Close)

	return redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
}

func Test_handlerRegisterUser(t *testing.T) {
	rdb := setupRedis(t)
	config := NewConfig(rdb)

	// basic register
	body := bytes.NewBuffer([]byte(`{
	  "email": "user@example.com",
	  "username": "johndoe34",
	  "password": "superSecret123"
}`))

	r := httptest.NewRequest("POST", "/register", body)

	w := httptest.NewRecorder()

	config.ServeHTTP(w, r)
	require.Equal(t, http.StatusCreated, w.Code)

	got := User{}

	err := json.Unmarshal(w.Body.Bytes(), &got)
	require.NoError(t, err)

	expected := User{
		Username: "johndoe34",
		Email:    "user@example.com",
		ID:       "87f2839ee63c",
	}
	require.Equal(t, expected.Email, got.Email)
	require.Equal(t, expected.Username, got.Username)
	require.Equal(t, expected.ID, got.ID)

	// registering existing user

	body = bytes.NewBuffer([]byte(`{
	  "email": "user@example.com",
	  "username": "johndoe34",
	  "password": "superSecret123"
}`))

	r = httptest.NewRequest("POST", "/register", body)

	w = httptest.NewRecorder()

	config.ServeHTTP(w, r)

	require.Equal(t, http.StatusConflict, w.Code)

}

func Test_handlerLogin(t *testing.T) {
	config := NewConfig(setupRedis(t))

	config.SetJWTSecret(jwtSecretTest)

	body := bytes.NewBuffer([]byte(`{
	  "email": "user@example.com",
	  "username": "johnnytest34",
	  "password": "superSecret123"
}`))
	r := httptest.NewRequest("POST", "/register", body)
	w := httptest.NewRecorder()

	config.ServeHTTP(w, r)

	require.Equalf(t, http.StatusCreated, w.Code, "%s", w.Body.String())

	body = bytes.NewBuffer([]byte(`{
	    "key": "johnnytest34",
		"password": "superSecret123"
	}`))

	r = httptest.NewRequest("POST", "/login", body)
	w = httptest.NewRecorder()

	config.ServeHTTP(w, r)

	require.Equalf(t, http.StatusAccepted, w.Code, "%s", w.Body.String())

	type response struct {
		User
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}
	var got response

	err := json.Unmarshal(w.Body.Bytes(), &got)
	require.NoError(t, err)

	expected := response{
		User: User{
			Username: "johnnytest34",
			Email:    "user@example.com",
			ID:       "b9968d72fe9d",
		},
	}

	require.Equal(t, expected.Username, got.Username)
	require.Equal(t, expected.Email, got.Email)
	require.Equal(t, expected.ID, got.ID)
	require.Nil(t, got.HashedPassword)
	require.NotEmptyf(t, got.Token, "Token:%v", got.Token)
	require.NotEmptyf(t, got.RefreshToken, "Refresh-Token: %v", got.RefreshToken)

}

func Test_handlerDeleteUser(t *testing.T) {
	config := NewConfig(setupRedis(t))

	config.SetJWTSecret(jwtSecretTest)

	usersData := setupUser(config, t)

	type response struct {
		User
		Token         string `json:"token"`
		Refresh_Token string `json:"refresh_token"`
	}
	var resp response
	err := json.Unmarshal(usersData, &resp)
	require.NoError(t, err)

	body := bytes.NewBuffer([]byte(`{
	    "password": "superSecret123"
	}`))

	r := httptest.NewRequest("DELETE", "/user", body)
	r.Header.Set("Authorization", "Bearer "+resp.Token)
	r.Header.Set("X-Refresh-Token", resp.Refresh_Token)

	w := httptest.NewRecorder()

	// delete the user
	config.ServeHTTP(w, r)

	require.Equalf(t, http.StatusNoContent, w.Code, "%s", w.Body.String())

	// trying to login on the deleted user

	body = bytes.NewBuffer([]byte(
		`{
	    "key": "johnnytest34",
		"password": "superSecret123"
		}`))

	r = httptest.NewRequest("POST", "/login", body)

	w = httptest.NewRecorder()

	config.ServeHTTP(w, r)

	require.Equalf(t, http.StatusNoContent, w.Code, "%s", w.Body.String())
}

func Test_handlerRevokeToken(t *testing.T) {
	config := NewConfig(setupRedis(t))

	config.SetJWTSecret(jwtSecretTest)

	usersData := setupUser(config, t)

	type response struct {
		User
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}
	var resp response
	err := json.Unmarshal(usersData, &resp)
	require.NoError(t, err)

	// token validation
	hash := auth.HashRefreshToken(resp.RefreshToken)
	id, err := config.redis.Get(context.Background(), hash).Result()
	require.NoError(t, err)
	require.Equal(t, resp.ID, id)

	// revoking the token
	w := httptest.NewRecorder()

	r := httptest.NewRequest("POST", "/revoke", nil)
	r.Header.Set("Authorization", "Bearer "+resp.Token)
	r.Header.Set("X-Refresh-Token", resp.RefreshToken)

	config.ServeHTTP(w, r)

	require.Equalf(t, http.StatusNoContent, w.Code, "%s", w.Body.String())

	// token validation again (should be invalid)
	hash = auth.HashRefreshToken(resp.RefreshToken)
	id, err = config.redis.Get(r.Context(), hash).Result()
	require.Error(t, err)
	require.ErrorIs(t, err, redis.Nil)

}

func Test_handlerUpdateUser(t *testing.T) {
	config := NewConfig(setupRedis(t))

	config.SetJWTSecret(jwtSecretTest)

	usersData := setupUser(config, t)

	type response struct {
		User
		Token         string `json:"token"`
		Refresh_Token string `json:"refresh_token"`
	}
	var resp response
	err := json.Unmarshal(usersData, &resp)
	require.NoError(t, err)

	// update password
	body := bytes.NewBuffer([]byte(`{
	"password": "superSecret123",
	"new_password": "newSuperSecret123"
	}`))
	r := httptest.NewRequest("PUT", "/user", body)
	w := httptest.NewRecorder()

	config.handlerUpdateUser(w, r, &resp.User)

	require.Equalf(t, http.StatusAccepted, w.Code, "%s", w.Body.String())

	// trying to login with the new password
	body = bytes.NewBuffer([]byte(`{
	   "key": "user@example.com",
	   "password": "newSuperSecret123"
	}`))

	r = httptest.NewRequest("POST", "/login", body)
	w = httptest.NewRecorder()

	config.ServeHTTP(w, r)

	require.Equalf(t, http.StatusAccepted, w.Code, "%s",
		w.Body.String())
}

func Test_handlerRefresh(t *testing.T) {
	config := NewConfig(setupRedis(t))

	config.SetJWTSecret(jwtSecretTest)

	usersData := setupUser(config, t)

	type response struct {
		User
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}
	var resp response
	err := json.Unmarshal(usersData, &resp)
	require.NoError(t, err)

	r := httptest.NewRequest("POST", "/refresh", nil)
	w := httptest.NewRecorder()

	r.Header.Set("X-Refresh-Token", resp.RefreshToken)

	config.ServeHTTP(w, r)

	require.Equalf(t, http.StatusAccepted, w.Code, "%s", w.Body.String())

	// invalidate the previous token
	hash := auth.HashRefreshToken(resp.RefreshToken)
	err = config.redis.Get(r.Context(), hash).Err()
	require.Error(t, err)
	require.ErrorIs(t, err, redis.Nil)

	// validate the new token
	resp = response{}
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	require.NotEmpty(t, resp.Token)
	require.NotEmpty(t, resp.RefreshToken)

	hash = auth.HashRefreshToken(resp.RefreshToken)
	err = config.redis.Get(r.Context(), hash).Err()
	require.NoError(t, err)

}

func Test_handlerCreateLibrary(t *testing.T) {
	config := NewConfig(setupRedis(t))

	config.SetJWTSecret(jwtSecretTest)

	usersData := setupUser(config, t)

	type response struct {
		User
		RefreshToken string `json:"refresh_token"`
		Token        string `json:"token"`
	}
	var resp response
	err := json.Unmarshal(usersData, &resp)
	require.NoError(t, err)

	body := bytes.NewBuffer([]byte(`{
	   "title": "Title Test 123",
	   "private": true
	}`))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/libraries", body)

	r.Header.Set("X-Refresh-Token", resp.RefreshToken)
	r.Header.Set("Authorization", "Bearer "+resp.Token)

	config.ServeHTTP(w, r)

	require.Equal(t, http.StatusCreated, w.Code)

	var lib Library

	err = json.Unmarshal(w.Body.Bytes(), &lib)
	require.NoError(t, err)

	exist, err := config.redis.HExists(r.Context(), LibraryTable, lib.ID).Result()
	require.NoError(t, err)
	require.True(t, exist)

}

func Test_handlerGetLibrary(t *testing.T) {
	config := NewConfig(setupRedis(t))

	config.SetJWTSecret(jwtSecretTest)

	usersLibraryData := setupUsersLibrary(config, t)

	var lib Library

	err := json.Unmarshal(usersLibraryData, &lib)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/libraries/"+lib.ID, nil)

	config.ServeHTTP(w, r)

	require.Equalf(t, http.StatusOK, w.Code, "%s", w.Body.String())

}

func Test_handlerDeleteLibrary(t *testing.T) {
	config := NewConfig(setupRedis(t))

	config.SetJWTSecret(jwtSecretTest)

	usersLibraryData := setupUsersLibrary(config, t)

	var lib Library

	err := json.Unmarshal(usersLibraryData, &lib)
	require.NoError(t, err)

	body := bytes.NewBuffer([]byte(`{
	  "key": "johnnytest34",
	  "password": "superSecret123"
	}`))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/login", body)

	config.ServeHTTP(w, r)

	type response struct {
		Token string `json:"token"`
	}
	var resp response
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	w = httptest.NewRecorder()
	r = httptest.NewRequest("DELETE", "/libraries/"+lib.ID, nil)
	r.Header.Set("Authorization", "Bearer "+resp.Token)

	config.ServeHTTP(w, r)

	require.Equalf(t, http.StatusNoContent, w.Code, "%s", w.Body.String())

	exist, err := config.redis.HExists(context.Background(), LibraryTable, lib.ID).Result()
	require.NoError(t, err)
	require.False(t, exist)
}

func Test_handlerGetUsersLibraries(t *testing.T) {
	config := NewConfig(setupRedis(t), withTesting())

	config.SetJWTSecret(jwtSecretTest)

	_ = setupUsersLibrary(config, t)

	body := bytes.NewBuffer([]byte(`{
	  "key": "johnnytest34",
	  "password": "superSecret123"
	}`))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/login", body)

	config.ServeHTTP(w, r)

	type response struct {
		Token string `json:"token"`
	}
	var resp response
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	w = httptest.NewRecorder()
	r = httptest.NewRequest("GET", "/libraries", nil)
	r.Header.Set("Authorization", "Bearer "+resp.Token)

	config.ServeHTTP(w, r)

	require.Equal(t, http.StatusAccepted, w.Code, "%s", w.Body.String())

}

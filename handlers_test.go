package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

var jwtSecretTest = "34236121r2311d"
var hmacSecretTest = []byte("34267331lew134")

func setupUser(cfg *Config, t *testing.T) []byte {

	body := bytes.NewBuffer([]byte(
		`{
	  "email": "user@example.com",
	  "username": "johnnytest34",
	  "password": "superSecret123"
	    }`))
	r := httptest.NewRequest("POST", "/register", body)
	w := httptest.NewRecorder()

	cfg.handlerRegisterUser(w, r)

	require.Equal(t, http.StatusCreated, w.Code)

	body = bytes.NewBuffer([]byte(
		`{
	    "key": "johnnytest34",
		"password": "superSecret123"
		}`))

	r = httptest.NewRequest("POST", "/login", body)
	w = httptest.NewRecorder()

	cfg.handlerLogin(w, r)

	require.Equal(t, http.StatusAccepted, w.Code)
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

	config.handlerRegisterUser(w, r)
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

	config.handlerRegisterUser(w, r)

	require.Equal(t, http.StatusConflict, w.Code)

}

func Test_handlerLogin(t *testing.T) {
	rdb := setupRedis(t)
	config := NewConfig(rdb)
	config.SetJWTSecret(jwtSecretTest)
	config.SetHMACSecret(hmacSecretTest)
	body := bytes.NewBuffer([]byte(`{
	  "email": "user@example.com",
	  "username": "johnnytest34",
	  "password": "superSecret123"
}`))
	r := httptest.NewRequest("POST", "/register", body)
	w := httptest.NewRecorder()

	config.handlerRegisterUser(w, r)

	require.Equalf(t, http.StatusCreated, w.Code, "%v", w.Body.String())

	body = bytes.NewBuffer([]byte(`{
	    "key": "johnnytest34",
		"password": "superSecret123"
	}`))

	r = httptest.NewRequest("POST", "/login", body)
	w = httptest.NewRecorder()

	config.handlerLogin(w, r)

	require.Equal(t, http.StatusAccepted, w.Code)

	type response struct {
		User
		Token        string
		RefreshToken string
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
	require.NotEmpty(t, got.Token)
	require.NotEmpty(t, got.RefreshToken)

	rdb.FlushDB(context.Background())
}

func Test_middlewareAuth(t *testing.T) {
	config := NewConfig(setupRedis(t))

	config.SetJWTSecret(jwtSecretTest)
	config.SetHMACSecret(hmacSecretTest)

	usersData := setupUser(config, t)

	type response struct {
		User
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}

	var resp response

	err := json.Unmarshal(usersData, &resp)
	require.NoError(t, err)

	r := httptest.NewRequest("GET", "/user", nil)
	r.Header.Set("Authorization", "Bearer "+resp.Token)
	r.Header.Set("X-Refresh-Token", resp.RefreshToken)

	w := httptest.NewRecorder()

	config.handlerGetUser(w, r, &resp.User)

	require.Equal(t, http.StatusAccepted, w.Code)

	var got User

	err = json.Unmarshal(w.Body.Bytes(), &got)

	require.Equal(t, resp.User, got)

}

func Test_handlerDeleteUser(t *testing.T) {
	cfg := NewConfig(setupRedis(t))

	cfg.SetJWTSecret(jwtSecretTest)
	cfg.SetHMACSecret(hmacSecretTest)

	usersData := setupUser(cfg, t)

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
	cfg.handlerDeleteUser(w, r, &resp.User)

	require.Equalf(t, http.StatusNoContent, w.Code, "%s", w.Body.String())

	// trying to login on the deleted user

	body = bytes.NewBuffer([]byte(
		`{
	    "key": "johnnytest34",
		"password": "superSecret123"
		}`))

	r = httptest.NewRequest("POST", "/login", body)

	w = httptest.NewRecorder()

	cfg.handlerLogin(w, r)

	require.Equalf(t, http.StatusNoContent, w.Code, "%s", w.Body.String())
}

func Test_handlerRevokeToken(t *testing.T) {
	cfg := NewConfig(setupRedis(t))

	cfg.SetJWTSecret(jwtSecretTest)
	cfg.SetHMACSecret(hmacSecretTest)

	usersData := setupUser(cfg, t)

	type response struct {
		User
		Token         string `json:"token"`
		Refresh_Token string `json:"refresh_token"`
	}
	var resp response
	err := json.Unmarshal(usersData, &resp)
	require.NoError(t, err)

	w := httptest.NewRecorder()

	r := httptest.NewRequest("POST", "/revoke", nil)
	r.Header.Set("Authorization", "Bearer "+resp.Token)
	r.Header.Set("X-Refresh-Token", resp.Refresh_Token)

	// revoking the refresh token
	cfg.handlerRevokeToken(w, r, &resp.User)

	require.Equalf(t, http.StatusNoContent, w.Code, "%s", w.Body.String())

	// trying to access an authed handler
	w = httptest.NewRecorder()

	r = httptest.NewRequest("GET", "/user", nil)
	r.Header.Set("Authorization", "Bearer "+resp.Token)
	r.Header.Set("X-Refresh-Token", resp.Refresh_Token)

	cfg.handlerGetUser(w, r, &resp.User)

}

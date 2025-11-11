package main

const ()

type User struct {
	ID             string `json:"id"`
	Username       string `json:"username"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
	HashedPassword []byte
	Email          string `json:"email"`
}

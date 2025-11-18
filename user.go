package main

type User struct {
	ID             string
	Username       string
	CreatedAt      string
	UpdatedAt      string
	HashedPassword []byte
	Email          string
}

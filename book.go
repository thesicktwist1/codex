package main

import (
	"strings"
)

type Status uint32

const (
	Reading Status = 1 << iota
	ToRead
	Finished
	DNF
)

type Book struct {
	ID   string `json:"id"`
	Info struct {
		Title         string   `json:"title"`
		Authors       []string `json:"authors"`
		Publisher     string   `json:"publisher"`
		PublishedDate string   `json:"publishedDate"`
		Description   string   `json:"description"`
		PageCount     int      `json:"pageCount"`
		MainCategory  string   `json:"mainCategory"`
		Categories    []string `json:"categories"`
	} `json:"volumeInfo"`
}

type Library struct {
	ID        string
	Owner     string
	Title     string
	CreatedAt string
	UpdatedAt string
	BookIDs   []string
	Private   bool
}

type Review struct {
	BookID      string
	UserID      string
	Description string
	CreatedAt   string
	UpdatedAt   string
	Status      Status
	Note        int
	CurrentPage int
	Private     bool
}

type Tracker struct {
	Book   Book
	Review Review
}

func (s Status) String() string {
	var b strings.Builder
	if s.Has(Finished) {
		b.WriteString("FINISHED")
	}
	if s.Has(Reading) {
		b.WriteString("READING")
	}
	if s.Has(ToRead) {
		b.WriteString("TO READ")
	}
	if s.Has(DNF) {
		b.WriteString("DID NOT FINISH")
	}
	if b.Len() == 0 {
		return "[no status]"
	}
	return b.String()
}

func (s Status) Has(r Status) bool { return s&r != 0 }

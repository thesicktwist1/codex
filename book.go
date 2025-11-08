package main

import "strings"

type BookID string

type Status uint32

const (
	Reading Status = 1 << iota
	Finished
)

type Book struct {
	Id            string
	Title         string
	Description   string
	Authors       []string
	Publishers    []string
	PublishedAt   string
	PageCount     int
	MainCategory  string
	SubCategories []string
}

type Library struct {
	ID      string
	Title   string
	Content []Content
	Private bool
}

type Content struct {
	ID          BookID
	Status      Status
	Note        int
	CurrentPage int
	Review      string
	UserID      string
}

func (s Status) String() string {
	var b strings.Builder
	if s.Has(Finished) {
		b.WriteString("FINISHED")
	}
	if s.Has(Reading) {
		b.WriteString("READING")
	}
	if b.Len() == 0 {
		return "[no status]"
	}
	return b.String()
}

func (s Status) Has(r Status) bool { return s&r != 0 }

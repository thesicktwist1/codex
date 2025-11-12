package main

import "strings"

type BookID string

type Status uint32

const (
	Reading Status = 1 << iota
	ToRead
	Finished
	DNF
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
	ID         string
	Owner      string
	Title      string
	CreatedAt  string
	UpdatedAt  string
	TrackerIDs []string
	Private    bool
}

type Tracker struct {
	BookID      string
	UserID      string
	Status      Status
	Note        int
	CurrentPage int
}

type Tracked struct {
	Book    Book
	Tracker Tracker
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

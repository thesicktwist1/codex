package main

type BookList struct {
	Items []struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
		Info struct {
			Title   string   `json:"title"`
			Authors []string `json:"authors"`
		} `json:"volumeInfo"`
	} `json:"items"`
}

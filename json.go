package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

func respondWithJSON(w http.ResponseWriter, status int, payload interface{}) {
	data, err := json.Marshal(payload)
	if err != nil {
		slog.Error("error unmarshaling payload", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, err = w.Write(data)
	if err != nil {
		slog.Error("error writing payload", "err", err)
	}
}

func emptyResponse(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

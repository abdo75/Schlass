package httputil

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

func WriteJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("failed to encode JSON response", "err", err)
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
	}
}

func WriteError(w http.ResponseWriter, status int, code, message string) {
	WriteJSON(w, status, map[string]string{
		"error":   code,
		"message": message,
	})
}

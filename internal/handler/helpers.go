package handler

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"secret-service/internal/errs"
)

type errorResponse struct {
	Error string `json:"error"`
}

func respondJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func respondErr(w http.ResponseWriter, err error) {
	if err == nil {
		respondJSON(w, http.StatusInternalServerError, errorResponse{Error: "internal server error"})
		return
	}

	status := http.StatusInternalServerError
	msg := "internal server error"
	defer func() {
		if status >= 500 {
			slog.Error("handler error", "error", err.Error(), "status", status)
		}
	}()

	switch {
	case errors.Is(err, errs.ErrNotFound):
		status, msg = http.StatusNotFound, "not found"
	case errors.Is(err, errs.ErrUnauthorized), errors.Is(err, errs.ErrInvalidCreds):
		status, msg = http.StatusUnauthorized, "unauthorized"
	case errors.Is(err, errs.ErrForbidden):
		status, msg = http.StatusForbidden, "forbidden"
	case errors.Is(err, errs.ErrConflict):
		status, msg = http.StatusConflict, "already exists"
	case errors.Is(err, errs.ErrInvalidInput):
		status, msg = http.StatusBadRequest, "invalid input"
	case errors.Is(err, errs.ErrAccessExpired):
		status, msg = http.StatusForbidden, "access expired"
	case errors.Is(err, errs.ErrSecretRevoked):
		status, msg = http.StatusGone, "secret revoked"
	}

	respondJSON(w, status, errorResponse{Error: msg})
}

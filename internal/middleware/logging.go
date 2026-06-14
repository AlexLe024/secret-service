package middleware

import (
	"log/slog"
	"net/http"
	"time"
)

// Logging logs each request with method, path, status, duration and request ID.
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(rec, r)

		slog.InfoContext(r.Context(), "http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"request_id", GetRequestID(r.Context()),
			"remote_addr", r.RemoteAddr,
		)
	})
}

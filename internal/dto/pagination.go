package dto

import (
	"net/http"
	"strconv"
)

const (
	defaultLimit = 20
	maxLimit     = 200
	// maxOffset bounds how deep a caller may page, preventing a single request
	// from forcing the database to scan and discard an arbitrarily large number
	// of rows (deep-offset resource exhaustion).
	maxOffset = 100000
)

// Page holds pagination parameters parsed from query string.
type Page struct {
	Limit  int
	Offset int
}

// ParsePage reads ?limit= and ?offset= from the request, applying sensible defaults.
func ParsePage(r *http.Request) Page {
	limit := defaultLimit
	offset := 0

	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	if offset > maxOffset {
		offset = maxOffset
	}

	return Page{Limit: limit, Offset: offset}
}

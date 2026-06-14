package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"secret-service/internal/domain"
	"secret-service/internal/token"
)

type contextKey string

const (
	principalKey contextKey = "principal"
	requestIDKey contextKey = "request_id"
)

type TokenParser interface {
	ParseClaims(token string) (*token.Claims, error)
}

// PrincipalValidator re-checks, on every request, that the principal behind a
// still-valid token is allowed to act (not blocked/revoked/deleted).
type PrincipalValidator interface {
	ValidatePrincipal(ctx context.Context, p domain.Principal) error
}

func Auth(parser TokenParser, validator PrincipalValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if !strings.HasPrefix(header, "Bearer ") {
				writeUnauthorized(w)
				return
			}

			tokenStr := strings.TrimPrefix(header, "Bearer ")
			claims, err := parser.ParseClaims(tokenStr)
			if err != nil {
				writeUnauthorized(w)
				return
			}

			principal := domain.Principal{
				ID:        claims.UserID,
				Type:      principalType(claims.Subject),
				ProjectID: claims.ProjectID,
				IsAdmin:   claims.IsAdmin,
			}

			if validator != nil {
				if err := validator.ValidatePrincipal(r.Context(), principal); err != nil {
					writeUnauthorized(w)
					return
				}
			}

			ctx := context.WithValue(r.Context(), principalKey, principal)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func principalType(subject string) domain.PrincipalType {
	if subject == token.SubjectServiceAccount {
		return domain.PrincipalServiceAccount
	}
	return domain.PrincipalUser
}

func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
}

// GetPrincipal returns the authenticated principal (user or service account).
func GetPrincipal(r *http.Request) (domain.Principal, bool) {
	p, ok := r.Context().Value(principalKey).(domain.Principal)
	return p, ok
}

// GetUserID returns the caller's id only when the principal is a human user.
// Service-account tokens deliberately return ok=false so that user-only
// endpoints reject them instead of treating the service account as a user.
func GetUserID(r *http.Request) (string, bool) {
	p, ok := GetPrincipal(r)
	if !ok || p.Type != domain.PrincipalUser {
		return "", false
	}
	return p.ID, true
}

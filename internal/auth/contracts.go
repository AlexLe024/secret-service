package auth

import (
	"context"

	"secret-service/internal/domain"
)

type PasswordHasher interface {
	Hash(password string) (string, error)
	Compare(hash, password string) error
	// DummyCompare burns comparison time on the not-found path to mitigate
	// timing-based user enumeration.
	DummyCompare(password string)
}

type TokenProvider interface {
	Generate(userID string) (string, error)
	GenerateWithClaims(userID string, isAdmin bool) (string, error)
}

type AuditService interface {
	Log(ctx context.Context, event domain.AuditEvent) error
}

package errs

import "errors"

var (
	ErrUnauthorized  = errors.New("unauthorized")
	ErrForbidden     = errors.New("forbidden")
	ErrNotFound      = errors.New("not found")
	ErrConflict      = errors.New("conflict")
	ErrInvalidInput  = errors.New("invalid input")
	ErrInvalidCreds  = errors.New("invalid credentials")
	ErrSecretRevoked = errors.New("secret revoked")
	ErrAccessExpired = errors.New("access expired")
)

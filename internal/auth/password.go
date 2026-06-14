package auth

import (
	"golang.org/x/crypto/bcrypt"

	"secret-service/internal/errs"
)

const (
	// MinPasswordLength is the minimum accepted password length.
	MinPasswordLength = 8
	// MaxPasswordLength is bcrypt's hard limit: it silently ignores any bytes
	// beyond 72, so we reject longer inputs instead of hashing a truncated one.
	MaxPasswordLength = 72
)

// dummyHash is a valid bcrypt hash used to equalize the timing of the
// authentication path when the account does not exist, mitigating user
// enumeration via response timing.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("timing-equalizer"), bcrypt.DefaultCost)

// ValidatePassword enforces length bounds before hashing.
func ValidatePassword(password string) error {
	if len(password) < MinPasswordLength || len(password) > MaxPasswordLength {
		return errs.ErrInvalidInput
	}
	return nil
}

type BcryptHasher struct{}

func NewBcryptHasher() *BcryptHasher {
	return &BcryptHasher{}
}

func (h *BcryptHasher) Hash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func (h *BcryptHasher) Compare(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// DummyCompare performs a bcrypt comparison against a fixed hash so that the
// not-found login path costs roughly the same time as a real password check.
func (h *BcryptHasher) DummyCompare(password string) {
	_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
}

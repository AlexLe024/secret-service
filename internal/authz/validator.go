// Package authz provides per-request validation of an authenticated principal,
// ensuring a token that is still cryptographically valid is rejected once the
// underlying user is blocked/deleted or the service account is revoked.
package authz

import (
	"context"

	"secret-service/internal/domain"
	"secret-service/internal/errs"
)

type UserRepository interface {
	GetByID(ctx context.Context, id string) (*domain.User, error)
}

type ServiceAccountRepository interface {
	GetByID(ctx context.Context, id string) (*domain.ServiceAccount, error)
}

// Validator checks that the principal behind a request is still allowed to act.
type Validator struct {
	users UserRepository
	sas   ServiceAccountRepository
}

func NewValidator(users UserRepository, sas ServiceAccountRepository) *Validator {
	return &Validator{users: users, sas: sas}
}

// ValidatePrincipal returns an error when the principal is no longer valid:
// the user does not exist or is blocked, or the service account is missing or
// not active. This closes the gap where a previously issued JWT outlives a
// block/revocation until its expiry.
func (v *Validator) ValidatePrincipal(ctx context.Context, p domain.Principal) error {
	if p.IsServiceAccount() {
		sa, err := v.sas.GetByID(ctx, p.ID)
		if err != nil || sa.Status != domain.ServiceAccountStatusActive {
			return errs.ErrUnauthorized
		}
		return nil
	}

	user, err := v.users.GetByID(ctx, p.ID)
	if err != nil || user.IsBlocked {
		return errs.ErrUnauthorized
	}
	return nil
}

package access

import (
	"context"

	"secret-service/internal/domain"
)

type Repository interface {
	CreateGrant(ctx context.Context, grant *domain.AccessGrant) error
	DeleteGrant(ctx context.Context, secretID, userID string) error
	GetGrant(ctx context.Context, secretID, userID string) (*domain.AccessGrant, error)
	ListGrants(ctx context.Context, secretID string) ([]domain.AccessGrant, error)
}

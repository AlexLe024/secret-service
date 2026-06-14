package auth

import (
	"context"

	"secret-service/internal/domain"
)

type UserRepository interface {
	Create(ctx context.Context, user *domain.User) error
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	GetByID(ctx context.Context, id string) (*domain.User, error)
	ListAll(ctx context.Context, limit, offset int) ([]domain.User, error)
	Count(ctx context.Context) (int, error)
	Block(ctx context.Context, id string) error
	Unblock(ctx context.Context, id string) error
	UpdateDisplayName(ctx context.Context, id, displayName string) error
}

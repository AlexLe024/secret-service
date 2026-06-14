package admin

import (
	"context"

	"secret-service/internal/domain"
	"secret-service/internal/dto"
)

// StatsRepository fetches aggregated system statistics in a single query.
type StatsRepository interface {
	GetStats(ctx context.Context) (*dto.StatsResponse, error)
}

// UserRepository is used to check whether the requesting user is an admin.
type UserRepository interface {
	GetByID(ctx context.Context, id string) (*domain.User, error)
}

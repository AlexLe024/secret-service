package admin

import (
	"context"

	"secret-service/internal/dto"
	"secret-service/internal/errs"
)

type Service struct {
	stats StatsRepository
	users UserRepository
}

func NewService(stats StatsRepository, users UserRepository) *Service {
	return &Service{stats: stats, users: users}
}

// GetStats returns platform-wide statistics. Only admins may call this.
func (s *Service) GetStats(ctx context.Context, actorUserID string) (*dto.StatsResponse, error) {
	user, err := s.users.GetByID(ctx, actorUserID)
	if err != nil {
		return nil, err
	}
	if !user.IsAdmin {
		return nil, errs.ErrForbidden
	}
	return s.stats.GetStats(ctx)
}

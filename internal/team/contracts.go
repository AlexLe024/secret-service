package team

import (
	"context"

	"secret-service/internal/domain"
)

type Repository interface {
	CreateTeam(ctx context.Context, team *domain.Team) error
	GetByID(ctx context.Context, teamID string) (*domain.Team, error)
	ListByUser(ctx context.Context, userID string) ([]domain.Team, error)
	AddMember(ctx context.Context, member *domain.TeamMember) error
	GetMember(ctx context.Context, teamID, userID string) (*domain.TeamMember, error)
	RemoveMember(ctx context.Context, teamID, userID string) error
	ListMembers(ctx context.Context, teamID string) ([]domain.TeamMember, error)
}

type AuditService interface {
	Log(ctx context.Context, event domain.AuditEvent) error
}

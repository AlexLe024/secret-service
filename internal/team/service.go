package team

import (
	"context"
	"time"

	"github.com/google/uuid"

	"secret-service/internal/domain"
	"secret-service/internal/errs"
)

type Service struct {
	repo  Repository
	audit AuditService
}

func NewService(repo Repository, audit AuditService) *Service {
	return &Service{repo: repo, audit: audit}
}

func (s *Service) CreateTeam(ctx context.Context, actorUserID, name, description string) (*domain.Team, error) {
	now := time.Now()
	t := &domain.Team{
		ID:          uuid.NewString(),
		Name:        name,
		Description: description,
		CreatedBy:   actorUserID,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := s.repo.CreateTeam(ctx, t); err != nil {
		return nil, err
	}

	// Создатель автоматически становится owner
	member := &domain.TeamMember{
		ID:        uuid.NewString(),
		TeamID:    t.ID,
		UserID:    actorUserID,
		Role:      domain.TeamRoleOwner,
		CreatedAt: now,
	}
	if err := s.repo.AddMember(ctx, member); err != nil {
		return nil, err
	}

	teamID := t.ID
	_ = s.audit.Log(ctx, domain.AuditEvent{
		ID:          uuid.NewString(),
		ActorUserID: &actorUserID,
		ProjectID:   &teamID,
		EventType:   domain.AuditEventType("team_created"),
		CreatedAt:   now,
	})

	return t, nil
}

func (s *Service) ListUserTeams(ctx context.Context, userID string) ([]domain.Team, error) {
	return s.repo.ListByUser(ctx, userID)
}

func (s *Service) AddMember(ctx context.Context, actorUserID, teamID, userID string, role domain.TeamRole) error {
	// Проверяем что актор — owner команды
	actorMember, err := s.repo.GetMember(ctx, teamID, actorUserID)
	if err != nil {
		return errs.ErrForbidden
	}
	if actorMember.Role != domain.TeamRoleOwner {
		return errs.ErrForbidden
	}

	member := &domain.TeamMember{
		ID:        uuid.NewString(),
		TeamID:    teamID,
		UserID:    userID,
		Role:      role,
		CreatedAt: time.Now(),
	}
	return s.repo.AddMember(ctx, member)
}

func (s *Service) RemoveMember(ctx context.Context, actorUserID, teamID, userID string) error {
	actorMember, err := s.repo.GetMember(ctx, teamID, actorUserID)
	if err != nil {
		return errs.ErrForbidden
	}
	if actorMember.Role != domain.TeamRoleOwner {
		return errs.ErrForbidden
	}
	return s.repo.RemoveMember(ctx, teamID, userID)
}

func (s *Service) ListMembers(ctx context.Context, teamID string) ([]domain.TeamMember, error) {
	return s.repo.ListMembers(ctx, teamID)
}

func (s *Service) GetByID(ctx context.Context, teamID string) (*domain.Team, error) {
	return s.repo.GetByID(ctx, teamID)
}

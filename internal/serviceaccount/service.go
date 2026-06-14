package serviceaccount

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"secret-service/internal/domain"
	"secret-service/internal/errs"
)

type Service struct {
	repo        Repository
	projectRepo ProjectRepository
	audit       AuditService
}

func NewService(repo Repository, projectRepo ProjectRepository, audit AuditService) *Service {
	return &Service{repo: repo, projectRepo: projectRepo, audit: audit}
}

// Create создаёт сервисный аккаунт и возвращает plaintext токен (показывается только один раз)
func (s *Service) Create(ctx context.Context, actorUserID, projectID, name, description string) (*domain.ServiceAccount, string, error) {
	actor, err := s.projectRepo.GetMember(ctx, projectID, actorUserID)
	if err != nil {
		return nil, "", errs.ErrForbidden
	}
	if actor.Role != domain.ProjectRoleAdmin && actor.Role != domain.ProjectRoleManager {
		return nil, "", errs.ErrForbidden
	}

	// Генерируем случайный токен
	rawToken, err := generateToken()
	if err != nil {
		return nil, "", fmt.Errorf("generate token: %w", err)
	}

	// Храним только хэш
	tokenHash, err := bcrypt.GenerateFromPassword([]byte(rawToken), bcrypt.DefaultCost)
	if err != nil {
		return nil, "", fmt.Errorf("hash token: %w", err)
	}

	now := time.Now()
	sa := &domain.ServiceAccount{
		ID:          uuid.NewString(),
		ProjectID:   projectID,
		Name:        name,
		Description: description,
		TokenHash:   string(tokenHash),
		Status:      domain.ServiceAccountStatusActive,
		CreatedBy:   actorUserID,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := s.repo.Create(ctx, sa); err != nil {
		return nil, "", err
	}

	_ = s.audit.Log(ctx, domain.AuditEvent{
		ID:          uuid.NewString(),
		ActorUserID: &actorUserID,
		ProjectID:   &projectID,
		EventType:   domain.AuditEventType("service_account_created"),
		CreatedAt:   now,
	})

	return sa, rawToken, nil
}

// Authenticate проверяет токен и возвращает сервисный аккаунт
func (s *Service) Authenticate(ctx context.Context, saID, rawToken string) (*domain.ServiceAccount, error) {
	sa, err := s.repo.GetByID(ctx, saID)
	if err != nil {
		return nil, errs.ErrInvalidCreds
	}

	if sa.Status != domain.ServiceAccountStatusActive {
		return nil, errs.ErrUnauthorized
	}

	if err := bcrypt.CompareHashAndPassword([]byte(sa.TokenHash), []byte(rawToken)); err != nil {
		return nil, errs.ErrInvalidCreds
	}

	_ = s.audit.Log(ctx, domain.AuditEvent{
		ID:        uuid.NewString(),
		ProjectID: &sa.ProjectID,
		EventType: domain.AuditEventType("service_account_login"),
		CreatedAt: time.Now(),
	})

	return sa, nil
}

// Revoke отзывает сервисный аккаунт
func (s *Service) Revoke(ctx context.Context, actorUserID, saID string) error {
	sa, err := s.repo.GetByID(ctx, saID)
	if err != nil {
		return err
	}

	actor, err := s.projectRepo.GetMember(ctx, sa.ProjectID, actorUserID)
	if err != nil {
		return errs.ErrForbidden
	}
	if actor.Role != domain.ProjectRoleAdmin && actor.Role != domain.ProjectRoleManager {
		return errs.ErrForbidden
	}

	if err := s.repo.UpdateStatus(ctx, saID, domain.ServiceAccountStatusRevoked); err != nil {
		return err
	}

	_ = s.audit.Log(ctx, domain.AuditEvent{
		ID:          uuid.NewString(),
		ActorUserID: &actorUserID,
		ProjectID:   &sa.ProjectID,
		EventType:   domain.AuditEventType("service_account_revoked"),
		CreatedAt:   time.Now(),
	})

	return nil
}

func (s *Service) ListByProject(ctx context.Context, actorUserID, projectID string) ([]domain.ServiceAccount, error) {
	member, err := s.projectRepo.GetMember(ctx, projectID, actorUserID)
	if err != nil {
		return nil, errs.ErrForbidden
	}
	// Listing service accounts exposes credential-bearing metadata, so it is
	// restricted to the same admin/manager roles that may create or revoke them.
	if member.Role != domain.ProjectRoleAdmin && member.Role != domain.ProjectRoleManager {
		return nil, errs.ErrForbidden
	}
	return s.repo.ListByProject(ctx, projectID)
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "sa_" + hex.EncodeToString(b), nil
}

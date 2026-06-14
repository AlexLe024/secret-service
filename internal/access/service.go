package access

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"secret-service/internal/domain"
	"secret-service/internal/errs"
)

type Service struct {
	repo        Repository
	projectRepo ProjectRepository
	secretRepo  SecretRepository
	audit       AuditService
}

func NewService(repo Repository, projectRepo ProjectRepository, secretRepo SecretRepository, audit AuditService) *Service {
	return &Service{
		repo:        repo,
		projectRepo: projectRepo,
		secretRepo:  secretRepo,
		audit:       audit,
	}
}

// ensureSecretInProject verifies that the secret exists and actually belongs to
// the given project. This prevents cross-project IDOR where an actor authorized
// on project A manipulates grants of a secret living in project B by passing a
// foreign secretID in the URL.
func (s *Service) ensureSecretInProject(ctx context.Context, projectID, secretID string) error {
	secret, err := s.secretRepo.GetSecretByID(ctx, secretID)
	if err != nil {
		return err
	}
	if secret.ProjectID != projectID {
		return errs.ErrNotFound
	}
	return nil
}

func (s *Service) GrantAccess(
	ctx context.Context,
	actorUserID, projectID, secretID, userID string,
	expiresAt *time.Time,
) error {
	actor, err := s.projectRepo.GetMember(ctx, projectID, actorUserID)
	if err != nil {
		return errs.ErrForbidden
	}
	if actor.Role != domain.ProjectRoleAdmin && actor.Role != domain.ProjectRoleManager {
		return errs.ErrForbidden
	}
	if err := s.ensureSecretInProject(ctx, projectID, secretID); err != nil {
		return err
	}

	grant := &domain.AccessGrant{
		ID:        uuid.NewString(),
		SecretID:  secretID,
		UserID:    userID,
		GrantedBy: actorUserID,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}

	if err := s.repo.CreateGrant(ctx, grant); err != nil {
		return err
	}

	_ = s.audit.Log(ctx, domain.AuditEvent{
		ID:          uuid.NewString(),
		ActorUserID: &actorUserID,
		ProjectID:   &projectID,
		SecretID:    &secretID,
		EventType:   domain.AuditAccessGranted,
		CreatedAt:   time.Now(),
	})

	return nil
}

func (s *Service) RevokeAccess(ctx context.Context, actorUserID, projectID, secretID, userID string) error {
	actor, err := s.projectRepo.GetMember(ctx, projectID, actorUserID)
	if err != nil {
		return errs.ErrForbidden
	}
	if actor.Role != domain.ProjectRoleAdmin && actor.Role != domain.ProjectRoleManager {
		return errs.ErrForbidden
	}
	if err := s.ensureSecretInProject(ctx, projectID, secretID); err != nil {
		return err
	}

	if err := s.repo.DeleteGrant(ctx, secretID, userID); err != nil {
		return err
	}

	_ = s.audit.Log(ctx, domain.AuditEvent{
		ID:          uuid.NewString(),
		ActorUserID: &actorUserID,
		ProjectID:   &projectID,
		SecretID:    &secretID,
		EventType:   domain.AuditAccessRevoked,
		CreatedAt:   time.Now(),
	})

	return nil
}

func (s *Service) ListGrants(ctx context.Context, actorUserID, projectID, secretID string) ([]domain.AccessGrant, error) {
	member, err := s.projectRepo.GetMember(ctx, projectID, actorUserID)
	if err != nil {
		return nil, errs.ErrForbidden
	}
	// Only admins and managers can see the full grant list
	if member.Role != domain.ProjectRoleAdmin && member.Role != domain.ProjectRoleManager {
		return nil, errs.ErrForbidden
	}
	if err := s.ensureSecretInProject(ctx, projectID, secretID); err != nil {
		return nil, err
	}
	return s.repo.ListGrants(ctx, secretID)
}

func (s *Service) CanReadSecret(ctx context.Context, projectID, secretID, userID string) (bool, error) {
	member, err := s.projectRepo.GetMember(ctx, projectID, userID)
	if err != nil {
		return false, err
	}

	if member.Role == domain.ProjectRoleAdmin || member.Role == domain.ProjectRoleManager {
		return true, nil
	}

	grant, err := s.repo.GetGrant(ctx, secretID, userID)
	if err != nil {
		if errors.Is(err, errs.ErrNotFound) {
			return false, errs.ErrForbidden
		}
		return false, err
	}

	if grant.ExpiresAt != nil && grant.ExpiresAt.Before(time.Now()) {
		return false, errs.ErrAccessExpired
	}

	return true, nil
}

package audit

import (
	"context"
	"log/slog"

	"secret-service/internal/domain"
	"secret-service/internal/errs"
)

type UserRepository interface {
	GetByID(ctx context.Context, id string) (*domain.User, error)
}

type ProjectRepository interface {
	GetMember(ctx context.Context, projectID, userID string) (*domain.ProjectMember, error)
}

type Service struct {
	repo        Repository
	users       UserRepository
	projectRepo ProjectRepository
}

func NewService(repo Repository, users UserRepository, projectRepo ProjectRepository) *Service {
	return &Service{
		repo:        repo,
		users:       users,
		projectRepo: projectRepo,
	}
}

// Log persists an audit event. Callers intentionally do not fail their main
// operation when auditing fails, so Log surfaces any persistence error here as
// a high-visibility log line rather than letting it be silently discarded at
// every call site.
func (s *Service) Log(ctx context.Context, event domain.AuditEvent) error {
	if err := s.repo.CreateEvent(ctx, &event); err != nil {
		slog.ErrorContext(ctx, "audit event persistence failed",
			"event_type", event.EventType,
			"project_id", derefStr(event.ProjectID),
			"secret_id", derefStr(event.SecretID),
			"error", err,
		)
		return err
	}
	return nil
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (s *Service) ListProjectEvents(ctx context.Context, projectID string) ([]domain.AuditEvent, error) {
	return s.repo.ListProjectEvents(ctx, projectID)
}

func (s *Service) ListSecretEvents(ctx context.Context, secretID string) ([]domain.AuditEvent, error) {
	return s.repo.ListSecretEvents(ctx, secretID)
}

// ListEvents returns audit events with authorization:
//   - if f.ProjectID is set, the actor must be a member of that project (any role) or a system admin;
//   - if f.ProjectID is not set (global scope), the actor must be a system admin.
func (s *Service) ListEvents(ctx context.Context, actorUserID string, f domain.AuditFilter) ([]domain.AuditEvent, error) {
	actor, err := s.users.GetByID(ctx, actorUserID)
	if err != nil {
		return nil, err
	}

	if f.ProjectID != nil && *f.ProjectID != "" {
		if !actor.IsAdmin {
			if _, err := s.projectRepo.GetMember(ctx, *f.ProjectID, actorUserID); err != nil {
				return nil, errs.ErrForbidden
			}
		}
	} else {
		if !actor.IsAdmin {
			return nil, errs.ErrForbidden
		}
	}

	return s.repo.ListEvents(ctx, f)
}

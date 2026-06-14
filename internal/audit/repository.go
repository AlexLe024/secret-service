package audit

import (
	"context"

	"secret-service/internal/domain"
)

type Repository interface {
	CreateEvent(ctx context.Context, event *domain.AuditEvent) error
	ListProjectEvents(ctx context.Context, projectID string) ([]domain.AuditEvent, error)
	ListSecretEvents(ctx context.Context, secretID string) ([]domain.AuditEvent, error)
	ListEvents(ctx context.Context, f domain.AuditFilter) ([]domain.AuditEvent, error)
}

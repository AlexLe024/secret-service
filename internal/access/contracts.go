package access

import (
	"context"

	"secret-service/internal/domain"
)

type ProjectRepository interface {
	GetMember(ctx context.Context, projectID, userID string) (*domain.ProjectMember, error)
}

type SecretRepository interface {
	GetSecretByID(ctx context.Context, secretID string) (*domain.Secret, error)
}

type AuditService interface {
	Log(ctx context.Context, event domain.AuditEvent) error
}

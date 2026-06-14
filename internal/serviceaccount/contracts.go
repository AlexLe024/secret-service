package serviceaccount

import (
	"context"

	"secret-service/internal/domain"
)

type Repository interface {
	Create(ctx context.Context, sa *domain.ServiceAccount) error
	GetByID(ctx context.Context, id string) (*domain.ServiceAccount, error)
	GetByTokenHash(ctx context.Context, tokenHash string) (*domain.ServiceAccount, error)
	ListByProject(ctx context.Context, projectID string) ([]domain.ServiceAccount, error)
	UpdateStatus(ctx context.Context, id string, status domain.ServiceAccountStatus) error
}

type ProjectRepository interface {
	GetMember(ctx context.Context, projectID, userID string) (*domain.ProjectMember, error)
}

type AuditService interface {
	Log(ctx context.Context, event domain.AuditEvent) error
}

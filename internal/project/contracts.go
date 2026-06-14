package project

import (
	"context"

	"secret-service/internal/domain"
)

type AuditService interface {
	Log(ctx context.Context, event domain.AuditEvent) error
}

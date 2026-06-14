package secret

import (
	"context"
	"time"

	"secret-service/internal/domain"
)

type Repository interface {
	CreateSecret(ctx context.Context, secret *domain.Secret) error
	GetSecretByID(ctx context.Context, secretID string) (*domain.Secret, error)
	ListSecretsByProject(ctx context.Context, projectID string, f domain.SecretFilter, limit, offset int) ([]domain.Secret, error)
	UpdateSecretStatus(ctx context.Context, secretID string, status domain.SecretStatus) error

	CreateVersion(ctx context.Context, version *domain.SecretVersion) error
	GetCurrentVersion(ctx context.Context, secretID string) (*domain.SecretVersion, error)
	GetVersionByNumber(ctx context.Context, secretID string, version int) (*domain.SecretVersion, error)
	ListVersions(ctx context.Context, secretID string) ([]domain.SecretVersion, error)
	GetNextVersionNumber(ctx context.Context, secretID string) (int, error)
	ClearCurrentVersion(ctx context.Context, secretID string) error
	SetCurrentVersion(ctx context.Context, secretID string, version int) error

	// Атомарные операции, оборачивающие несколько мутаций в одну транзакцию.
	CreateSecretWithVersion(ctx context.Context, secret *domain.Secret, version *domain.SecretVersion) error
	RotateInTx(ctx context.Context, secretID, versionID, createdBy string, encryptedValue, nonce []byte, now time.Time) (int, error)

	// ListExpiringSecrets returns active secrets expiring within the next withinDays days.
	ListExpiringSecrets(ctx context.Context, projectID string, withinDays int) ([]domain.Secret, error)
}

package secret

import (
	"context"

	"secret-service/internal/domain"
)

type ProjectRepository interface {
	GetMember(ctx context.Context, projectID, userID string) (*domain.ProjectMember, error)
}

type CryptoService interface {
	Encrypt(plainText []byte) (cipherText []byte, nonce []byte, err error)
	Decrypt(cipherText []byte, nonce []byte) ([]byte, error)
}

type AccessService interface {
	CanReadSecret(ctx context.Context, projectID, secretID, userID string) (bool, error)
}

type AuditService interface {
	Log(ctx context.Context, event domain.AuditEvent) error
}

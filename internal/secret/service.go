package secret

import (
	"context"
	"time"

	"github.com/google/uuid"

	"secret-service/internal/domain"
	"secret-service/internal/errs"
)

type Service struct {
	repo        Repository
	projectRepo ProjectRepository
	crypto      CryptoService
	access      AccessService
	audit       AuditService
}

func NewService(
	repo Repository,
	projectRepo ProjectRepository,
	crypto CryptoService,
	access AccessService,
	audit AuditService,
) *Service {
	return &Service{
		repo:        repo,
		projectRepo: projectRepo,
		crypto:      crypto,
		access:      access,
		audit:       audit,
	}
}

// authorizeProjectRead grants read access to a project for the given principal.
// Human users must be project members; a service account may read only within
// the single project its token is bound to.
func (s *Service) authorizeProjectRead(ctx context.Context, p domain.Principal, projectID string) error {
	if p.IsServiceAccount() {
		if p.ProjectID != projectID {
			return errs.ErrForbidden
		}
		return nil
	}
	if _, err := s.projectRepo.GetMember(ctx, projectID, p.ID); err != nil {
		return err
	}
	return nil
}

// actorRef returns the audit actor reference for a principal. Service accounts
// are not rows in users(id), so their actor reference is left nil to avoid
// violating the audit_events.actor_user_id foreign key.
func actorRef(p domain.Principal) *string {
	if p.Type == domain.PrincipalUser {
		id := p.ID
		return &id
	}
	return nil
}

func (s *Service) CreateSecret(
	ctx context.Context,
	actorUserID, projectID, name, description, value, environment string,
	tags []string,
	expiresAt *time.Time,
) (*domain.Secret, error) {
	member, err := s.projectRepo.GetMember(ctx, projectID, actorUserID)
	if err != nil {
		return nil, err
	}

	if member.Role != domain.ProjectRoleAdmin && member.Role != domain.ProjectRoleManager {
		return nil, errs.ErrForbidden
	}

	encryptedValue, nonce, err := s.crypto.Encrypt([]byte(value))
	if err != nil {
		return nil, err
	}

	now := time.Now()

	env := domain.SecretEnvironment(environment)
	if env != domain.EnvDevelopment && env != domain.EnvStaging && env != domain.EnvProduction {
		env = domain.EnvProduction
	}

	if tags == nil {
		tags = []string{}
	}

	secret := &domain.Secret{
		ID:          uuid.NewString(),
		ProjectID:   projectID,
		Name:        name,
		Description: description,
		Status:      domain.SecretStatusActive,
		Environment: env,
		Tags:        tags,
		ExpiresAt:   expiresAt,
		CreatedBy:   actorUserID,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	version := &domain.SecretVersion{
		ID:             uuid.NewString(),
		SecretID:       secret.ID,
		Version:        1,
		EncryptedValue: encryptedValue,
		Nonce:          nonce,
		IsCurrent:      true,
		CreatedBy:      actorUserID,
		CreatedAt:      now,
	}

	// Атомарно: либо обе строки (секрет + первая версия) попадают в БД, либо ни одна.
	if err := s.repo.CreateSecretWithVersion(ctx, secret, version); err != nil {
		return nil, err
	}

	_ = s.audit.Log(ctx, domain.AuditEvent{
		ID:          uuid.NewString(),
		ActorUserID: &actorUserID,
		ProjectID:   &projectID,
		SecretID:    &secret.ID,
		EventType:   domain.AuditSecretCreated,
		CreatedAt:   now,
	})

	return secret, nil
}

func (s *Service) GetSecret(ctx context.Context, actorUserID, secretID string) (*domain.Secret, error) {
	secret, err := s.repo.GetSecretByID(ctx, secretID)
	if err != nil {
		return nil, err
	}

	_, err = s.projectRepo.GetMember(ctx, secret.ProjectID, actorUserID)
	if err != nil {
		return nil, err
	}

	return secret, nil
}

func (s *Service) GetSecretValue(ctx context.Context, p domain.Principal, secretID string) (string, error) {
	secret, err := s.repo.GetSecretByID(ctx, secretID)
	if err != nil {
		return "", err
	}

	if secret.Status == domain.SecretStatusRevoked {
		return "", errs.ErrSecretRevoked
	}

	if secret.ExpiresAt != nil && time.Now().After(*secret.ExpiresAt) {
		return "", errs.ErrSecretRevoked
	}

	if err := s.authorizeSecretRead(ctx, p, secret); err != nil {
		_ = s.audit.Log(ctx, domain.AuditEvent{
			ID:          uuid.NewString(),
			ActorUserID: actorRef(p),
			ProjectID:   &secret.ProjectID,
			SecretID:    &secret.ID,
			EventType:   domain.AuditSecretReadDenied,
			CreatedAt:   time.Now(),
		})
		return "", err
	}

	version, err := s.repo.GetCurrentVersion(ctx, secret.ID)
	if err != nil {
		return "", err
	}

	plainValue, err := s.crypto.Decrypt(version.EncryptedValue, version.Nonce)
	if err != nil {
		return "", err
	}

	_ = s.audit.Log(ctx, domain.AuditEvent{
		ID:          uuid.NewString(),
		ActorUserID: actorRef(p),
		ProjectID:   &secret.ProjectID,
		SecretID:    &secret.ID,
		EventType:   domain.AuditSecretRead,
		CreatedAt:   time.Now(),
	})

	return string(plainValue), nil
}

// authorizeSecretRead decides whether the principal may read this secret's value.
// Service accounts may read any secret in their bound project; human users go
// through the role/grant-based access check.
func (s *Service) authorizeSecretRead(ctx context.Context, p domain.Principal, secret *domain.Secret) error {
	if p.IsServiceAccount() {
		if p.ProjectID != secret.ProjectID {
			return errs.ErrForbidden
		}
		return nil
	}

	canRead, err := s.access.CanReadSecret(ctx, secret.ProjectID, secret.ID, p.ID)
	if err != nil {
		return err
	}
	if !canRead {
		return errs.ErrForbidden
	}
	return nil
}

func (s *Service) RevokeSecret(ctx context.Context, actorUserID, secretID string) error {
	secret, err := s.repo.GetSecretByID(ctx, secretID)
	if err != nil {
		return err
	}

	member, err := s.projectRepo.GetMember(ctx, secret.ProjectID, actorUserID)
	if err != nil {
		return err
	}

	if member.Role != domain.ProjectRoleAdmin && member.Role != domain.ProjectRoleManager {
		return errs.ErrForbidden
	}

	if err := s.repo.UpdateSecretStatus(ctx, secretID, domain.SecretStatusRevoked); err != nil {
		return err
	}

	_ = s.audit.Log(ctx, domain.AuditEvent{
		ID:          uuid.NewString(),
		ActorUserID: &actorUserID,
		ProjectID:   &secret.ProjectID,
		SecretID:    &secret.ID,
		EventType:   domain.AuditSecretRevoked,
		CreatedAt:   time.Now(),
	})

	return nil
}

func (s *Service) RotateSecret(ctx context.Context, actorUserID, secretID, newValue string) error {
	secret, err := s.repo.GetSecretByID(ctx, secretID)
	if err != nil {
		return err
	}

	member, err := s.projectRepo.GetMember(ctx, secret.ProjectID, actorUserID)
	if err != nil {
		return err
	}

	if member.Role != domain.ProjectRoleAdmin && member.Role != domain.ProjectRoleManager {
		return errs.ErrForbidden
	}

	encryptedValue, nonce, err := s.crypto.Encrypt([]byte(newValue))
	if err != nil {
		return err
	}

	// Атомарно: блокируем строку секрета, считаем следующий номер версии,
	// снимаем флаг is_current со старой версии и вставляем новую.
	// Если любой шаг падает — откатывается всё, секрет остаётся в консистентном состоянии.
	if _, err := s.repo.RotateInTx(ctx, secretID, uuid.NewString(), actorUserID, encryptedValue, nonce, time.Now()); err != nil {
		return err
	}

	_ = s.audit.Log(ctx, domain.AuditEvent{
		ID:          uuid.NewString(),
		ActorUserID: &actorUserID,
		ProjectID:   &secret.ProjectID,
		SecretID:    &secret.ID,
		EventType:   domain.AuditSecretRotated,
		CreatedAt:   time.Now(),
	})

	return nil
}
func (s *Service) ListVersions(ctx context.Context, p domain.Principal, secretID string) ([]domain.SecretVersion, error) {
	secret, err := s.repo.GetSecretByID(ctx, secretID)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeProjectRead(ctx, p, secret.ProjectID); err != nil {
		return nil, err
	}
	return s.repo.ListVersions(ctx, secretID)
}

func (s *Service) RollbackSecret(ctx context.Context, actorUserID, secretID string, version int) error {
	secret, err := s.repo.GetSecretByID(ctx, secretID)
	if err != nil {
		return err
	}

	member, err := s.projectRepo.GetMember(ctx, secret.ProjectID, actorUserID)
	if err != nil {
		return errs.ErrForbidden
	}
	if member.Role != domain.ProjectRoleAdmin && member.Role != domain.ProjectRoleManager {
		return errs.ErrForbidden
	}

	// Verify the target version exists
	if _, err := s.repo.GetVersionByNumber(ctx, secretID, version); err != nil {
		return errs.ErrNotFound
	}

	if err := s.repo.SetCurrentVersion(ctx, secretID, version); err != nil {
		return err
	}

	_ = s.audit.Log(ctx, domain.AuditEvent{
		ID:          uuid.NewString(),
		ActorUserID: &actorUserID,
		ProjectID:   &secret.ProjectID,
		SecretID:    &secret.ID,
		EventType:   domain.AuditEventType("secret_rolled_back"),
		CreatedAt:   time.Now(),
	})

	return nil
}

func (s *Service) ListSecretsByProject(ctx context.Context, p domain.Principal, projectID string, f domain.SecretFilter, limit, offset int) ([]domain.Secret, error) {
	if err := s.authorizeProjectRead(ctx, p, projectID); err != nil {
		return nil, err
	}
	return s.repo.ListSecretsByProject(ctx, projectID, f, limit, offset)
}

// ListExpiringSecrets returns active secrets in the project that expire within the given number of days.
func (s *Service) ListExpiringSecrets(ctx context.Context, p domain.Principal, projectID string, days int) ([]domain.Secret, error) {
	if err := s.authorizeProjectRead(ctx, p, projectID); err != nil {
		return nil, err
	}
	if days <= 0 {
		days = 7
	}
	return s.repo.ListExpiringSecrets(ctx, projectID, days)
}

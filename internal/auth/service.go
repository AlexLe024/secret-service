package auth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"secret-service/internal/domain"
	"secret-service/internal/errs"
)

type Service struct {
	users  UserRepository
	hasher PasswordHasher
	tokens TokenProvider
	audit  AuditService
}

func NewService(
	users UserRepository,
	hasher PasswordHasher,
	tokens TokenProvider,
	audit AuditService,
) *Service {
	return &Service{
		users:  users,
		hasher: hasher,
		tokens: tokens,
		audit:  audit,
	}
}

func (s *Service) CreateUser(ctx context.Context, email, password string) (*domain.User, error) {
	if err := ValidatePassword(password); err != nil {
		return nil, err
	}

	passwordHash, err := s.hasher.Hash(password)
	if err != nil {
		return nil, err
	}

	// Первый зарегистрированный пользователь становится системным администратором
	count, err := s.users.Count(ctx)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	user := &domain.User{
		ID:           uuid.NewString(),
		Email:        email,
		DisplayName:  email,
		PasswordHash: passwordHash,
		IsAdmin:      count == 0,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.users.Create(ctx, user); err != nil {
		return nil, err
	}

	_ = s.audit.Log(ctx, domain.AuditEvent{
		ID:        uuid.NewString(),
		EventType: domain.AuditUserRegistered,
		CreatedAt: now,
	})

	return user, nil
}

func (s *Service) Login(ctx context.Context, email, password string) (string, error) {
	user, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		// Equalize timing and return an indistinguishable error so the response
		// cannot be used to tell whether the email is registered.
		s.hasher.DummyCompare(password)
		if errors.Is(err, errs.ErrNotFound) {
			return "", errs.ErrInvalidCreds
		}
		return "", err
	}

	if err := s.hasher.Compare(user.PasswordHash, password); err != nil {
		return "", errs.ErrInvalidCreds
	}

	// Block status is only revealed to a caller who already proved the password,
	// so it does not become an account-enumeration oracle.
	if user.IsBlocked {
		return "", errs.ErrForbidden
	}

	token, err := s.tokens.GenerateWithClaims(user.ID, user.IsAdmin)
	if err != nil {
		return "", err
	}

	userID := user.ID
	_ = s.audit.Log(ctx, domain.AuditEvent{
		ID:          uuid.NewString(),
		ActorUserID: &userID,
		EventType:   domain.AuditUserLoggedIn,
		CreatedAt:   time.Now(),
	})

	return token, nil
}

func (s *Service) GetByID(ctx context.Context, id string) (*domain.User, error) {
	return s.users.GetByID(ctx, id)
}

func (s *Service) BlockUser(ctx context.Context, actorUserID, targetUserID string) error {
	// Проверяем что актор — системный администратор
	actor, err := s.users.GetByID(ctx, actorUserID)
	if err != nil {
		return err
	}
	if !actor.IsAdmin {
		return errs.ErrForbidden
	}
	if actorUserID == targetUserID {
		return errs.ErrInvalidInput
	}

	if err := s.users.Block(ctx, targetUserID); err != nil {
		return err
	}

	_ = s.audit.Log(ctx, domain.AuditEvent{
		ID:          uuid.NewString(),
		ActorUserID: &actorUserID,
		EventType:   domain.AuditEventType("user_blocked"),
		CreatedAt:   time.Now(),
	})

	return nil
}

func (s *Service) UnblockUser(ctx context.Context, actorUserID, targetUserID string) error {
	actor, err := s.users.GetByID(ctx, actorUserID)
	if err != nil {
		return err
	}
	if !actor.IsAdmin {
		return errs.ErrForbidden
	}
	if actorUserID == targetUserID {
		return errs.ErrInvalidInput
	}

	if err := s.users.Unblock(ctx, targetUserID); err != nil {
		return err
	}

	_ = s.audit.Log(ctx, domain.AuditEvent{
		ID:          uuid.NewString(),
		ActorUserID: &actorUserID,
		EventType:   domain.AuditEventType("user_unblocked"),
		CreatedAt:   time.Now(),
	})

	return nil
}

func (s *Service) ListUsers(ctx context.Context, actorUserID string, limit, offset int) ([]domain.User, error) {
	actor, err := s.users.GetByID(ctx, actorUserID)
	if err != nil {
		return nil, err
	}
	if !actor.IsAdmin {
		return nil, errs.ErrForbidden
	}
	return s.users.ListAll(ctx, limit, offset)
}

func (s *Service) UpdateDisplayName(ctx context.Context, userID, displayName string) (*domain.User, error) {
	if err := s.users.UpdateDisplayName(ctx, userID, displayName); err != nil {
		return nil, err
	}
	return s.users.GetByID(ctx, userID)
}

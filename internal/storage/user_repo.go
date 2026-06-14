package storage

import (
	"context"
	"errors"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"secret-service/internal/domain"
	"secret-service/internal/errs"
)

type UserRepo struct {
	db *sqlx.DB
}

func NewUserRepo(db *sqlx.DB) *UserRepo {
	return &UserRepo{db: db}
}

func (r *UserRepo) Create(ctx context.Context, user *domain.User) error {
	q := `INSERT INTO users (id, email, display_name, password_hash, is_blocked, is_admin, created_at, updated_at)
	      VALUES (:id, :email, :display_name, :password_hash, :is_blocked, :is_admin, :created_at, :updated_at)`
	_, err := r.db.NamedExecContext(ctx, q, user)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return errs.ErrConflict
		}
		return err
	}
	return nil
}

func (r *UserRepo) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	var user domain.User
	err := r.db.GetContext(ctx, &user, `SELECT * FROM users WHERE email = $1`, email)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &user, nil
}

func (r *UserRepo) GetByID(ctx context.Context, id string) (*domain.User, error) {
	var user domain.User
	err := r.db.GetContext(ctx, &user, `SELECT * FROM users WHERE id = $1`, id)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &user, nil
}

func (r *UserRepo) Count(ctx context.Context) (int, error) {
	var count int
	err := r.db.GetContext(ctx, &count, `SELECT COUNT(*) FROM users`)
	return count, err
}

func (r *UserRepo) Block(ctx context.Context, id string) error {
	q := `UPDATE users SET is_blocked = TRUE, updated_at = NOW() WHERE id = $1`
	res, err := r.db.ExecContext(ctx, q, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

func (r *UserRepo) Unblock(ctx context.Context, id string) error {
	q := `UPDATE users SET is_blocked = FALSE, updated_at = NOW() WHERE id = $1`
	res, err := r.db.ExecContext(ctx, q, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

func (r *UserRepo) ListAll(ctx context.Context, limit, offset int) ([]domain.User, error) {
	users := make([]domain.User, 0)
	err := r.db.SelectContext(ctx, &users, `SELECT * FROM users ORDER BY created_at ASC LIMIT $1 OFFSET $2`, limit, offset)
	return users, err
}

func (r *UserRepo) UpdateDisplayName(ctx context.Context, id, displayName string) error {
	q := `UPDATE users SET display_name = $1, updated_at = NOW() WHERE id = $2`
	res, err := r.db.ExecContext(ctx, q, displayName, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

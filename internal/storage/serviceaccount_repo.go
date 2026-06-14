package storage

import (
	"context"
	"errors"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"secret-service/internal/domain"
	"secret-service/internal/errs"
)

type ServiceAccountRepo struct {
	db *sqlx.DB
}

func NewServiceAccountRepo(db *sqlx.DB) *ServiceAccountRepo {
	return &ServiceAccountRepo{db: db}
}

func (r *ServiceAccountRepo) Create(ctx context.Context, sa *domain.ServiceAccount) error {
	q := `INSERT INTO service_accounts (id, project_id, name, description, token_hash, status, created_by, created_at, updated_at)
	      VALUES (:id, :project_id, :name, :description, :token_hash, :status, :created_by, :created_at, :updated_at)`
	_, err := r.db.NamedExecContext(ctx, q, sa)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return errs.ErrConflict
		}
		return err
	}
	return nil
}

func (r *ServiceAccountRepo) GetByID(ctx context.Context, id string) (*domain.ServiceAccount, error) {
	var sa domain.ServiceAccount
	err := r.db.GetContext(ctx, &sa, `SELECT * FROM service_accounts WHERE id = $1`, id)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &sa, nil
}

func (r *ServiceAccountRepo) GetByTokenHash(ctx context.Context, tokenHash string) (*domain.ServiceAccount, error) {
	var sa domain.ServiceAccount
	err := r.db.GetContext(ctx, &sa, `SELECT * FROM service_accounts WHERE token_hash = $1`, tokenHash)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &sa, nil
}

func (r *ServiceAccountRepo) ListByProject(ctx context.Context, projectID string) ([]domain.ServiceAccount, error) {
	var accounts []domain.ServiceAccount
	q := `SELECT * FROM service_accounts WHERE project_id = $1 ORDER BY created_at DESC`
	if err := r.db.SelectContext(ctx, &accounts, q, projectID); err != nil {
		return nil, err
	}
	return accounts, nil
}

func (r *ServiceAccountRepo) UpdateStatus(ctx context.Context, id string, status domain.ServiceAccountStatus) error {
	q := `UPDATE service_accounts SET status = $1, updated_at = NOW() WHERE id = $2`
	res, err := r.db.ExecContext(ctx, q, status, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

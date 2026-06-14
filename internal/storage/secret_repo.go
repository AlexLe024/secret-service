package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"secret-service/internal/domain"
	"secret-service/internal/errs"
)

type SecretRepo struct {
	db *sqlx.DB
}

func NewSecretRepo(db *sqlx.DB) *SecretRepo {
	return &SecretRepo{db: db}
}

func (r *SecretRepo) CreateSecret(ctx context.Context, secret *domain.Secret) error {
	q := `INSERT INTO secrets (id, project_id, name, description, status, environment, tags, expires_at, created_by, created_at, updated_at)
	      VALUES (:id, :project_id, :name, :description, :status, :environment, :tags, :expires_at, :created_by, :created_at, :updated_at)`

	_, err := r.db.NamedExecContext(ctx, q, secret)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return errs.ErrConflict
		}
		return err
	}
	return nil
}

func (r *SecretRepo) GetSecretByID(ctx context.Context, secretID string) (*domain.Secret, error) {
	var s domain.Secret
	err := r.db.GetContext(ctx, &s, `SELECT * FROM secrets WHERE id = $1`, secretID)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &s, nil
}

func (r *SecretRepo) ListSecretsByProject(ctx context.Context, projectID string, f domain.SecretFilter, limit, offset int) ([]domain.Secret, error) {
	args := []interface{}{projectID}
	idx := 2
	where := "project_id = $1"

	if f.Environment != nil {
		where += fmt.Sprintf(" AND environment = $%d", idx)
		args = append(args, *f.Environment)
		idx++
	}
	if f.Status != nil {
		where += fmt.Sprintf(" AND status = $%d", idx)
		args = append(args, *f.Status)
		idx++
	}
	if f.Name != nil {
		where += fmt.Sprintf(" AND name ILIKE $%d", idx)
		args = append(args, "%"+*f.Name+"%")
		idx++
	}
	if len(f.Tags) > 0 {
		where += fmt.Sprintf(" AND tags @> $%d", idx)
		args = append(args, pq.StringArray(f.Tags))
		idx++
	}

	args = append(args, limit, offset)
	q := fmt.Sprintf(`SELECT * FROM secrets WHERE %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d`,
		where, idx, idx+1)

	var secrets []domain.Secret
	if err := r.db.SelectContext(ctx, &secrets, q, args...); err != nil {
		return nil, err
	}
	return secrets, nil
}

func (r *SecretRepo) UpdateSecretStatus(ctx context.Context, secretID string, status domain.SecretStatus) error {
	q := `UPDATE secrets SET status = $1, updated_at = NOW() WHERE id = $2`
	res, err := r.db.ExecContext(ctx, q, status, secretID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

func (r *SecretRepo) CreateVersion(ctx context.Context, v *domain.SecretVersion) error {
	q := `INSERT INTO secret_versions (id, secret_id, version, encrypted_value, nonce, is_current, created_by, created_at)
	      VALUES (:id, :secret_id, :version, :encrypted_value, :nonce, :is_current, :created_by, :created_at)`
	_, err := r.db.NamedExecContext(ctx, q, v)
	return err
}

func (r *SecretRepo) GetCurrentVersion(ctx context.Context, secretID string) (*domain.SecretVersion, error) {
	var v domain.SecretVersion
	q := `SELECT * FROM secret_versions WHERE secret_id = $1 AND is_current = TRUE LIMIT 1`
	err := r.db.GetContext(ctx, &v, q, secretID)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &v, nil
}

func (r *SecretRepo) GetNextVersionNumber(ctx context.Context, secretID string) (int, error) {
	var maxVersion int
	q := `SELECT COALESCE(MAX(version), 0) FROM secret_versions WHERE secret_id = $1`
	if err := r.db.GetContext(ctx, &maxVersion, q, secretID); err != nil {
		return 0, err
	}
	return maxVersion + 1, nil
}

func (r *SecretRepo) ClearCurrentVersion(ctx context.Context, secretID string) error {
	q := `UPDATE secret_versions SET is_current = FALSE WHERE secret_id = $1 AND is_current = TRUE`
	_, err := r.db.ExecContext(ctx, q, secretID)
	return err
}

func (r *SecretRepo) ListVersions(ctx context.Context, secretID string) ([]domain.SecretVersion, error) {
	versions := make([]domain.SecretVersion, 0)
	q := `SELECT id, secret_id, version, is_current, created_by, created_at
	      FROM secret_versions WHERE secret_id = $1 ORDER BY version DESC`
	if err := r.db.SelectContext(ctx, &versions, q, secretID); err != nil {
		return nil, err
	}
	return versions, nil
}

func (r *SecretRepo) GetVersionByNumber(ctx context.Context, secretID string, version int) (*domain.SecretVersion, error) {
	var v domain.SecretVersion
	q := `SELECT * FROM secret_versions WHERE secret_id = $1 AND version = $2`
	err := r.db.GetContext(ctx, &v, q, secretID, version)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &v, nil
}

func (r *SecretRepo) SetCurrentVersion(ctx context.Context, secretID string, version int) error {
	q := `UPDATE secret_versions SET is_current = (version = $1) WHERE secret_id = $2`
	_, err := r.db.ExecContext(ctx, q, version, secretID)
	return err
}

func (r *SecretRepo) ListExpiringSecrets(ctx context.Context, projectID string, withinDays int) ([]domain.Secret, error) {
	secrets := make([]domain.Secret, 0)
	// Includes already-expired-but-still-active secrets (expires_at in the past):
	// those are the ones most urgently in need of rotation, so they must not be
	// dropped from the "expiring" report.
	q := `SELECT * FROM secrets
	      WHERE project_id = $1
	        AND status = 'active'
	        AND expires_at IS NOT NULL
	        AND expires_at <= NOW() + ($2::int * interval '1 day')
	      ORDER BY expires_at ASC`
	if err := r.db.SelectContext(ctx, &secrets, q, projectID, withinDays); err != nil {
		return nil, err
	}
	return secrets, nil
}

// CreateSecretWithVersion atomically inserts the secret row and its first version
// in a single database transaction. Either both rows persist or neither does.
func (r *SecretRepo) CreateSecretWithVersion(ctx context.Context, secret *domain.Secret, version *domain.SecretVersion) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	insertSecret := `INSERT INTO secrets (id, project_id, name, description, status, environment, tags, expires_at, created_by, created_at, updated_at)
	                 VALUES (:id, :project_id, :name, :description, :status, :environment, :tags, :expires_at, :created_by, :created_at, :updated_at)`
	if _, err := tx.NamedExecContext(ctx, insertSecret, secret); err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return errs.ErrConflict
		}
		return err
	}

	insertVersion := `INSERT INTO secret_versions (id, secret_id, version, encrypted_value, nonce, is_current, created_by, created_at)
	                  VALUES (:id, :secret_id, :version, :encrypted_value, :nonce, :is_current, :created_by, :created_at)`
	if _, err := tx.NamedExecContext(ctx, insertVersion, version); err != nil {
		return err
	}

	return tx.Commit()
}

// RotateInTx atomically clears the current version flag and inserts the new version
// in a single transaction. Returns the assigned version number. Concurrent rotations
// on the same secret are serialised by SELECT ... FOR UPDATE on the row in `secrets`.
func (r *SecretRepo) RotateInTx(ctx context.Context, secretID, versionID, createdBy string, encryptedValue, nonce []byte, now time.Time) (int, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	// Lock the secret row so concurrent rotations don't both pick the same next version.
	var lockedID string
	if err := tx.GetContext(ctx, &lockedID, `SELECT id FROM secrets WHERE id = $1 FOR UPDATE`, secretID); err != nil {
		return 0, mapNotFound(err)
	}

	var maxVersion int
	if err := tx.GetContext(ctx, &maxVersion,
		`SELECT COALESCE(MAX(version), 0) FROM secret_versions WHERE secret_id = $1`, secretID); err != nil {
		return 0, err
	}
	nextVersion := maxVersion + 1

	if _, err := tx.ExecContext(ctx,
		`UPDATE secret_versions SET is_current = FALSE WHERE secret_id = $1 AND is_current = TRUE`, secretID); err != nil {
		return 0, err
	}

	insertVersion := `INSERT INTO secret_versions (id, secret_id, version, encrypted_value, nonce, is_current, created_by, created_at)
	                  VALUES ($1, $2, $3, $4, $5, TRUE, $6, $7)`
	if _, err := tx.ExecContext(ctx, insertVersion, versionID, secretID, nextVersion, encryptedValue, nonce, createdBy, now); err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return nextVersion, nil
}

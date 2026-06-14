package storage

import (
	"context"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"

	"secret-service/internal/domain"
	"secret-service/internal/errs"
)

// ---- AccessGrantRepo ----

type AccessGrantRepo struct {
	db *sqlx.DB
}

func NewAccessGrantRepo(db *sqlx.DB) *AccessGrantRepo {
	return &AccessGrantRepo{db: db}
}

func (r *AccessGrantRepo) CreateGrant(ctx context.Context, grant *domain.AccessGrant) error {
	q := `INSERT INTO access_grants (id, secret_id, user_id, granted_by, expires_at, created_at)
	      VALUES (:id, :secret_id, :user_id, :granted_by, :expires_at, :created_at)
	      ON CONFLICT (secret_id, user_id) DO UPDATE
	        SET granted_by = EXCLUDED.granted_by,
	            expires_at = EXCLUDED.expires_at,
	            created_at = EXCLUDED.created_at`
	_, err := r.db.NamedExecContext(ctx, q, grant)
	return err
}

func (r *AccessGrantRepo) DeleteGrant(ctx context.Context, secretID, userID string) error {
	q := `DELETE FROM access_grants WHERE secret_id = $1 AND user_id = $2`
	res, err := r.db.ExecContext(ctx, q, secretID, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

func (r *AccessGrantRepo) GetGrant(ctx context.Context, secretID, userID string) (*domain.AccessGrant, error) {
	var g domain.AccessGrant
	q := `SELECT * FROM access_grants WHERE secret_id = $1 AND user_id = $2`
	err := r.db.GetContext(ctx, &g, q, secretID, userID)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &g, nil
}

func (r *AccessGrantRepo) ListGrants(ctx context.Context, secretID string) ([]domain.AccessGrant, error) {
	grants := make([]domain.AccessGrant, 0)
	q := `SELECT * FROM access_grants WHERE secret_id = $1 ORDER BY created_at DESC`
	if err := r.db.SelectContext(ctx, &grants, q, secretID); err != nil {
		return nil, err
	}
	return grants, nil
}

// ---- AuditRepo ----

type AuditRepo struct {
	db *sqlx.DB
}

func NewAuditRepo(db *sqlx.DB) *AuditRepo {
	return &AuditRepo{db: db}
}

func (r *AuditRepo) CreateEvent(ctx context.Context, event *domain.AuditEvent) error {
	q := `INSERT INTO audit_events (id, actor_user_id, project_id, secret_id, event_type, metadata, created_at)
	      VALUES (:id, :actor_user_id, :project_id, :secret_id, :event_type, :metadata, :created_at)`
	_, err := r.db.NamedExecContext(ctx, q, event)
	return err
}

func (r *AuditRepo) ListProjectEvents(ctx context.Context, projectID string) ([]domain.AuditEvent, error) {
	var events []domain.AuditEvent
	q := `SELECT * FROM audit_events WHERE project_id = $1 ORDER BY created_at DESC LIMIT 500`
	if err := r.db.SelectContext(ctx, &events, q, projectID); err != nil {
		return nil, err
	}
	return events, nil
}

func (r *AuditRepo) ListSecretEvents(ctx context.Context, secretID string) ([]domain.AuditEvent, error) {
	var events []domain.AuditEvent
	q := `SELECT * FROM audit_events WHERE secret_id = $1 ORDER BY created_at DESC LIMIT 200`
	if err := r.db.SelectContext(ctx, &events, q, secretID); err != nil {
		return nil, err
	}
	return events, nil
}

func (r *AuditRepo) ListEvents(ctx context.Context, f domain.AuditFilter) ([]domain.AuditEvent, error) {
	var (
		conds []string
		args  []interface{}
		idx   = 1
	)

	if f.ProjectID != nil {
		conds = append(conds, fmt.Sprintf("project_id = $%d", idx))
		args = append(args, *f.ProjectID)
		idx++
	}
	if f.ActorUserID != nil {
		conds = append(conds, fmt.Sprintf("actor_user_id = $%d", idx))
		args = append(args, *f.ActorUserID)
		idx++
	}
	if f.SecretID != nil {
		conds = append(conds, fmt.Sprintf("secret_id = $%d", idx))
		args = append(args, *f.SecretID)
		idx++
	}
	if f.EventType != nil {
		conds = append(conds, fmt.Sprintf("event_type = $%d", idx))
		args = append(args, *f.EventType)
		idx++
	}
	if f.From != nil {
		conds = append(conds, fmt.Sprintf("created_at >= $%d", idx))
		args = append(args, *f.From)
		idx++
	}
	if f.To != nil {
		conds = append(conds, fmt.Sprintf("created_at <= $%d", idx))
		args = append(args, *f.To)
		idx++
	}

	limit := 100
	if f.Limit > 0 && f.Limit <= 500 {
		limit = f.Limit
	}

	q := "SELECT * FROM audit_events"
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += fmt.Sprintf(" ORDER BY created_at DESC LIMIT %d", limit)

	events := make([]domain.AuditEvent, 0)
	if err := r.db.SelectContext(ctx, &events, q, args...); err != nil {
		return nil, err
	}
	return events, nil
}

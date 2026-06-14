package storage

import (
	"context"

	"github.com/jmoiron/sqlx"

	"secret-service/internal/dto"
)

type StatsRepo struct {
	db *sqlx.DB
}

func NewStatsRepo(db *sqlx.DB) *StatsRepo {
	return &StatsRepo{db: db}
}

// GetStats runs a single multi-column aggregation query for platform-wide stats.
func (r *StatsRepo) GetStats(ctx context.Context) (*dto.StatsResponse, error) {
	var row struct {
		TotalUsers           int `db:"total_users"`
		TotalProjects        int `db:"total_projects"`
		TotalSecretsActive   int `db:"total_secrets_active"`
		TotalSecretsRevoked  int `db:"total_secrets_revoked"`
		TotalServiceAccounts int `db:"total_service_accounts"`
		AuditEventsLast24h   int `db:"audit_events_last_24h"`
		ExpiringSecrets7d    int `db:"expiring_secrets_7d"`
	}

	q := `SELECT
		(SELECT COUNT(*)::int FROM users)                                                                                AS total_users,
		(SELECT COUNT(*)::int FROM projects)                                                                             AS total_projects,
		(SELECT COUNT(*)::int FROM secrets  WHERE status = 'active')                                                     AS total_secrets_active,
		(SELECT COUNT(*)::int FROM secrets  WHERE status = 'revoked')                                                    AS total_secrets_revoked,
		(SELECT COUNT(*)::int FROM service_accounts WHERE status = 'active')                                             AS total_service_accounts,
		(SELECT COUNT(*)::int FROM audit_events WHERE created_at >= NOW() - interval '24 hours')                         AS audit_events_last_24h,
		(SELECT COUNT(*)::int FROM secrets  WHERE status = 'active' AND expires_at IS NOT NULL
		                                      AND expires_at > NOW() AND expires_at <= NOW() + interval '7 days')        AS expiring_secrets_7d`

	if err := r.db.GetContext(ctx, &row, q); err != nil {
		return nil, err
	}

	return &dto.StatsResponse{
		TotalUsers:           row.TotalUsers,
		TotalProjects:        row.TotalProjects,
		TotalSecretsActive:   row.TotalSecretsActive,
		TotalSecretsRevoked:  row.TotalSecretsRevoked,
		TotalServiceAccounts: row.TotalServiceAccounts,
		AuditEventsLast24h:   row.AuditEventsLast24h,
		ExpiringSecrets7d:    row.ExpiringSecrets7d,
	}, nil
}

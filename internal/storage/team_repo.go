package storage

import (
	"context"
	"errors"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"secret-service/internal/domain"
	"secret-service/internal/errs"
)

type TeamRepo struct {
	db *sqlx.DB
}

func NewTeamRepo(db *sqlx.DB) *TeamRepo {
	return &TeamRepo{db: db}
}

func (r *TeamRepo) CreateTeam(ctx context.Context, t *domain.Team) error {
	q := `INSERT INTO teams (id, name, description, created_by, created_at, updated_at)
	      VALUES (:id, :name, :description, :created_by, :created_at, :updated_at)`
	_, err := r.db.NamedExecContext(ctx, q, t)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return errs.ErrConflict
		}
		return err
	}
	return nil
}

func (r *TeamRepo) GetByID(ctx context.Context, teamID string) (*domain.Team, error) {
	var t domain.Team
	err := r.db.GetContext(ctx, &t, `SELECT * FROM teams WHERE id = $1`, teamID)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &t, nil
}

func (r *TeamRepo) ListByUser(ctx context.Context, userID string) ([]domain.Team, error) {
	var teams []domain.Team
	q := `SELECT t.* FROM teams t
	      JOIN team_members tm ON tm.team_id = t.id
	      WHERE tm.user_id = $1
	      ORDER BY t.created_at DESC`
	if err := r.db.SelectContext(ctx, &teams, q, userID); err != nil {
		return nil, err
	}
	return teams, nil
}

func (r *TeamRepo) AddMember(ctx context.Context, m *domain.TeamMember) error {
	q := `INSERT INTO team_members (id, team_id, user_id, role, created_at)
	      VALUES (:id, :team_id, :user_id, :role, :created_at)
	      ON CONFLICT (team_id, user_id) DO UPDATE SET role = EXCLUDED.role`
	_, err := r.db.NamedExecContext(ctx, q, m)
	return err
}

func (r *TeamRepo) GetMember(ctx context.Context, teamID, userID string) (*domain.TeamMember, error) {
	var m domain.TeamMember
	q := `SELECT * FROM team_members WHERE team_id = $1 AND user_id = $2`
	err := r.db.GetContext(ctx, &m, q, teamID, userID)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &m, nil
}

func (r *TeamRepo) RemoveMember(ctx context.Context, teamID, userID string) error {
	q := `DELETE FROM team_members WHERE team_id = $1 AND user_id = $2`
	res, err := r.db.ExecContext(ctx, q, teamID, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

func (r *TeamRepo) ListMembers(ctx context.Context, teamID string) ([]domain.TeamMember, error) {
	var members []domain.TeamMember
	q := `SELECT * FROM team_members WHERE team_id = $1 ORDER BY created_at`
	if err := r.db.SelectContext(ctx, &members, q, teamID); err != nil {
		return nil, err
	}
	return members, nil
}

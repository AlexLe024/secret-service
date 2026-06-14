package storage

import (
	"context"
	"errors"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"secret-service/internal/domain"
	"secret-service/internal/errs"
)

type ProjectRepo struct {
	db *sqlx.DB
}

func NewProjectRepo(db *sqlx.DB) *ProjectRepo {
	return &ProjectRepo{db: db}
}

func (r *ProjectRepo) CreateProject(ctx context.Context, project *domain.Project) error {
	q := `INSERT INTO projects (id, name, description, created_by, created_at, updated_at)
	      VALUES (:id, :name, :description, :created_by, :created_at, :updated_at)`

	_, err := r.db.NamedExecContext(ctx, q, project)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return errs.ErrConflict
		}
		return err
	}
	return nil
}

func (r *ProjectRepo) GetProjectByID(ctx context.Context, projectID string) (*domain.Project, error) {
	var p domain.Project
	err := r.db.GetContext(ctx, &p, `SELECT * FROM projects WHERE id = $1`, projectID)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &p, nil
}

func (r *ProjectRepo) ListProjectsByUser(ctx context.Context, userID string, limit, offset int) ([]domain.Project, error) {
	projects := make([]domain.Project, 0)
	q := `SELECT p.* FROM projects p
          JOIN project_members pm ON pm.project_id = p.id
          WHERE pm.user_id = $1
          ORDER BY p.created_at DESC LIMIT $2 OFFSET $3`

	if err := r.db.SelectContext(ctx, &projects, q, userID, limit, offset); err != nil {
		return nil, err
	}
	return projects, nil
}

func (r *ProjectRepo) AddMember(ctx context.Context, member *domain.ProjectMember) error {
	q := `INSERT INTO project_members (id, project_id, user_id, role, created_at)
	      VALUES (:id, :project_id, :user_id, :role, :created_at)
	      ON CONFLICT (project_id, user_id) DO UPDATE SET role = EXCLUDED.role`

	_, err := r.db.NamedExecContext(ctx, q, member)
	return err
}

func (r *ProjectRepo) GetMember(ctx context.Context, projectID, userID string) (*domain.ProjectMember, error) {
	var m domain.ProjectMember
	q := `SELECT * FROM project_members WHERE project_id = $1 AND user_id = $2`
	err := r.db.GetContext(ctx, &m, q, projectID, userID)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &m, nil
}

func (r *ProjectRepo) RemoveMember(ctx context.Context, projectID, userID string) error {
	q := `DELETE FROM project_members WHERE project_id = $1 AND user_id = $2`
	res, err := r.db.ExecContext(ctx, q, projectID, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

func (r *ProjectRepo) UpdateMemberRole(ctx context.Context, projectID, userID string, role domain.ProjectRole) error {
	q := `UPDATE project_members SET role = $1 WHERE project_id = $2 AND user_id = $3`
	res, err := r.db.ExecContext(ctx, q, role, projectID, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

func (r *ProjectRepo) ListMembers(ctx context.Context, projectID string, limit, offset int) ([]domain.ProjectMember, error) {
	members := make([]domain.ProjectMember, 0)
	q := `SELECT * FROM project_members WHERE project_id = $1 ORDER BY created_at ASC LIMIT $2 OFFSET $3`
	if err := r.db.SelectContext(ctx, &members, q, projectID, limit, offset); err != nil {
		return nil, err
	}
	return members, nil
}

func (r *ProjectRepo) AssignTeam(ctx context.Context, link *domain.ProjectTeam) error {
	q := `INSERT INTO project_teams (project_id, team_id, assigned_by, assigned_at)
	      VALUES (:project_id, :team_id, :assigned_by, :assigned_at)
	      ON CONFLICT (project_id, team_id) DO NOTHING`
	_, err := r.db.NamedExecContext(ctx, q, link)
	return err
}

func (r *ProjectRepo) UnassignTeam(ctx context.Context, projectID, teamID string) error {
	q := `DELETE FROM project_teams WHERE project_id = $1 AND team_id = $2`
	res, err := r.db.ExecContext(ctx, q, projectID, teamID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

func (r *ProjectRepo) ListProjectTeams(ctx context.Context, projectID string) ([]domain.ProjectTeam, error) {
	links := make([]domain.ProjectTeam, 0)
	q := `SELECT * FROM project_teams WHERE project_id = $1 ORDER BY assigned_at DESC`
	if err := r.db.SelectContext(ctx, &links, q, projectID); err != nil {
		return nil, err
	}
	return links, nil
}

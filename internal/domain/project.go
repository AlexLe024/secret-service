package domain

import "time"

type Project struct {
	ID          string    `db:"id"          json:"id"`
	Name        string    `db:"name"        json:"name"`
	Description string    `db:"description" json:"description"`
	TeamID      *string   `db:"team_id"     json:"team_id,omitempty"`
	CreatedBy   string    `db:"created_by"  json:"created_by"`
	CreatedAt   time.Time `db:"created_at"  json:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"  json:"updated_at"`
}

// ProjectTeam records a team that has been assigned to a project.
type ProjectTeam struct {
	ProjectID  string    `db:"project_id"  json:"project_id"`
	TeamID     string    `db:"team_id"     json:"team_id"`
	AssignedBy string    `db:"assigned_by" json:"assigned_by"`
	AssignedAt time.Time `db:"assigned_at" json:"assigned_at"`
}

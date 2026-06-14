package domain

import "time"

type ProjectRole string

const (
	ProjectRoleAdmin     ProjectRole = "admin"
	ProjectRoleManager   ProjectRole = "manager"
	ProjectRoleDeveloper ProjectRole = "developer"
)

type ProjectMember struct {
	ID        string      `db:"id" json:"id"`
	ProjectID string      `db:"project_id" json:"project_id"`
	UserID    string      `db:"user_id" json:"user_id"`
	Role      ProjectRole `db:"role" json:"role"`
	CreatedAt time.Time   `db:"created_at" json:"created_at"`
}

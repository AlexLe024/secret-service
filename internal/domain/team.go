package domain

import "time"

type Team struct {
	ID          string    `db:"id"          json:"id"`
	Name        string    `db:"name"        json:"name"`
	Description string    `db:"description" json:"description"`
	CreatedBy   string    `db:"created_by"  json:"created_by"`
	CreatedAt   time.Time `db:"created_at"  json:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"  json:"updated_at"`
}

type TeamRole string

const (
	TeamRoleOwner  TeamRole = "owner"
	TeamRoleMember TeamRole = "member"
)

type TeamMember struct {
	ID        string    `db:"id"         json:"id"`
	TeamID    string    `db:"team_id"    json:"team_id"`
	UserID    string    `db:"user_id"    json:"user_id"`
	Role      TeamRole  `db:"role"       json:"role"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}

package domain

import "time"

type AccessGrant struct {
	ID        string     `db:"id" json:"id"`
	SecretID  string     `db:"secret_id" json:"secret_id"`
	UserID    string     `db:"user_id" json:"user_id"`
	GrantedBy string     `db:"granted_by" json:"granted_by"`
	ExpiresAt *time.Time `db:"expires_at" json:"expires_at,omitempty"`
	CreatedAt time.Time  `db:"created_at" json:"created_at"`
}

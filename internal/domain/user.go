package domain

import "time"

type User struct {
	ID           string    `db:"id"            json:"id"`
	Email        string    `db:"email"         json:"email"`
	DisplayName  string    `db:"display_name"  json:"display_name"`
	PasswordHash string    `db:"password_hash" json:"-"`
	IsBlocked    bool      `db:"is_blocked"    json:"is_blocked"`
	IsAdmin      bool      `db:"is_admin"      json:"is_admin"`
	CreatedAt    time.Time `db:"created_at"    json:"created_at"`
	UpdatedAt    time.Time `db:"updated_at"    json:"updated_at"`
}

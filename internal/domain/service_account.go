package domain

import "time"

type ServiceAccountStatus string

const (
	ServiceAccountStatusActive  ServiceAccountStatus = "active"
	ServiceAccountStatusRevoked ServiceAccountStatus = "revoked"
)

type ServiceAccount struct {
	ID          string               `db:"id"            json:"id"`
	ProjectID   string               `db:"project_id"    json:"project_id"`
	Name        string               `db:"name"          json:"name"`
	Description string               `db:"description"   json:"description"`
	TokenHash   string               `db:"token_hash"    json:"-"`
	Status      ServiceAccountStatus `db:"status"        json:"status"`
	CreatedBy   string               `db:"created_by"    json:"created_by"`
	CreatedAt   time.Time            `db:"created_at"    json:"created_at"`
	UpdatedAt   time.Time            `db:"updated_at"    json:"updated_at"`
}

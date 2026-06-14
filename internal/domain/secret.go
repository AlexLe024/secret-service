package domain

import (
	"time"

	"github.com/lib/pq"
)

type SecretStatus string

const (
	SecretStatusActive  SecretStatus = "active"
	SecretStatusRevoked SecretStatus = "revoked"
)

type SecretEnvironment string

const (
	EnvDevelopment SecretEnvironment = "development"
	EnvStaging     SecretEnvironment = "staging"
	EnvProduction  SecretEnvironment = "production"
)

type Secret struct {
	ID          string            `db:"id" json:"id"`
	ProjectID   string            `db:"project_id" json:"project_id"`
	Name        string            `db:"name" json:"name"`
	Description string            `db:"description" json:"description"`
	Status      SecretStatus      `db:"status" json:"status"`
	Environment SecretEnvironment `db:"environment" json:"environment"`
	Tags        pq.StringArray    `db:"tags" json:"tags" swaggertype:"array,string"`
	ExpiresAt   *time.Time        `db:"expires_at" json:"expires_at,omitempty"`
	CreatedBy   string            `db:"created_by" json:"created_by"`
	CreatedAt   time.Time         `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time         `db:"updated_at" json:"updated_at"`
}

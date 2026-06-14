package dto

import "time"

type CreateSecretRequest struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Value       string     `json:"value"`
	Environment string     `json:"environment,omitempty"`
	Tags        []string   `json:"tags,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

type RotateSecretRequest struct {
	Value string `json:"value"`
}

type RollbackSecretRequest struct {
	Version int `json:"version"`
}

type GrantAccessRequest struct {
	UserID    string     `json:"user_id"`
	ExpiresAt *time.Time `json:"expires_at"`
}

type SecretValueResponse struct {
	SecretID string `json:"secret_id"`
	Value    string `json:"value"`
}

package dto

// StatsResponse is returned by GET /api/v1/admin/stats.
type StatsResponse struct {
	TotalUsers           int `json:"total_users"`
	TotalProjects        int `json:"total_projects"`
	TotalSecretsActive   int `json:"total_secrets_active"`
	TotalSecretsRevoked  int `json:"total_secrets_revoked"`
	TotalServiceAccounts int `json:"total_service_accounts"`
	AuditEventsLast24h   int `json:"audit_events_last_24h"`
	ExpiringSecrets7d    int `json:"expiring_secrets_7d"`
}

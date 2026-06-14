package domain

import "time"

// AuditFilter holds optional query parameters for listing audit events.
type AuditFilter struct {
	ProjectID   *string
	ActorUserID *string
	SecretID    *string
	EventType   *AuditEventType
	From        *time.Time
	To          *time.Time
	Limit       int
}

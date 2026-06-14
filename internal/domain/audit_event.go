package domain

import "time"

type AuditEventType string

const (
	AuditUserRegistered   AuditEventType = "user_registered"
	AuditUserLoggedIn     AuditEventType = "user_logged_in"
	AuditProjectCreated   AuditEventType = "project_created"
	AuditProjectMemberAdd AuditEventType = "project_member_added"
	AuditSecretCreated    AuditEventType = "secret_created"
	AuditSecretRead       AuditEventType = "secret_read"
	AuditSecretReadDenied AuditEventType = "secret_read_denied"
	AuditAccessGranted    AuditEventType = "access_granted"
	AuditAccessRevoked    AuditEventType = "access_revoked"
	AuditSecretRevoked    AuditEventType = "secret_revoked"
	AuditSecretRotated    AuditEventType = "secret_rotated"
)

type AuditEvent struct {
	ID          string         `db:"id" json:"id"`
	ActorUserID *string        `db:"actor_user_id" json:"actor_user_id,omitempty"`
	ProjectID   *string        `db:"project_id" json:"project_id,omitempty"`
	SecretID    *string        `db:"secret_id" json:"secret_id,omitempty"`
	EventType   AuditEventType `db:"event_type" json:"event_type"`
	Metadata    []byte         `db:"metadata" json:"metadata"`
	CreatedAt   time.Time      `db:"created_at" json:"created_at"`
}

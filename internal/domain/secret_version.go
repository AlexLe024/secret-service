package domain

import "time"

type SecretVersion struct {
	ID             string    `db:"id" json:"id"`
	SecretID       string    `db:"secret_id" json:"secret_id"`
	Version        int       `db:"version" json:"version"`
	EncryptedValue []byte    `db:"encrypted_value" json:"-"`
	Nonce          []byte    `db:"nonce" json:"-"`
	IsCurrent      bool      `db:"is_current" json:"is_current"`
	CreatedBy      string    `db:"created_by" json:"created_by"`
	CreatedAt      time.Time `db:"created_at" json:"created_at"`
}

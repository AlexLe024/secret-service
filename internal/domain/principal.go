package domain

// PrincipalType distinguishes the kind of authenticated caller behind a request.
type PrincipalType string

const (
	PrincipalUser           PrincipalType = "user"
	PrincipalServiceAccount PrincipalType = "service_account"
)

// Principal is the authenticated caller extracted from a bearer token. A human
// user and a service account are different security subjects and must not be
// treated interchangeably.
type Principal struct {
	ID        string
	Type      PrincipalType
	ProjectID string // bound project, set only for service accounts
	IsAdmin   bool
}

// IsServiceAccount reports whether the principal is a service account.
func (p Principal) IsServiceAccount() bool {
	return p.Type == PrincipalServiceAccount
}

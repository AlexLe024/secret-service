package domain

// SecretFilter holds optional query filters for listing secrets.
type SecretFilter struct {
	Environment *SecretEnvironment
	Status      *SecretStatus
	Name        *string
	// Tags filters secrets that contain ALL of the given tags (subset match).
	Tags []string
}

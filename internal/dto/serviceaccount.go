package dto

type CreateServiceAccountRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type ServiceAccountLoginRequest struct {
	ServiceAccountID string `json:"service_account_id"`
	Token            string `json:"token"`
}

type CreateServiceAccountResponse struct {
	ID          string `json:"id"`
	ProjectID   string `json:"project_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Token       string `json:"token"` // shown only on creation
	Warning     string `json:"warning"`
}

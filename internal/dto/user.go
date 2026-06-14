package dto

type CreateUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
type UpdateDisplayNameRequest struct {
	DisplayName string `json:"display_name"`
}

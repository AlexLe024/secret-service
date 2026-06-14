package dto

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
}

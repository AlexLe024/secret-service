package dto

type CreateTeamRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type AddTeamMemberRequest struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

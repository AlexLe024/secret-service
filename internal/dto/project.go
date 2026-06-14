package dto

type CreateProjectRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type AddProjectMemberRequest struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

type AssignTeamRequest struct {
	TeamID string `json:"team_id"`
	// Role assigned to each team member in the project. Defaults to "developer".
	Role string `json:"role,omitempty"`
}

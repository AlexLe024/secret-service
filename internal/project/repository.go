package project

import (
	"context"

	"secret-service/internal/domain"
)

type Repository interface {
	CreateProject(ctx context.Context, project *domain.Project) error
	ListProjectsByUser(ctx context.Context, userID string, limit, offset int) ([]domain.Project, error)
	AddMember(ctx context.Context, member *domain.ProjectMember) error
	RemoveMember(ctx context.Context, projectID, userID string) error
	UpdateMemberRole(ctx context.Context, projectID, userID string, role domain.ProjectRole) error
	ListMembers(ctx context.Context, projectID string, limit, offset int) ([]domain.ProjectMember, error)
	GetMember(ctx context.Context, projectID, userID string) (*domain.ProjectMember, error)
	GetProjectByID(ctx context.Context, projectID string) (*domain.Project, error)

	AssignTeam(ctx context.Context, link *domain.ProjectTeam) error
	UnassignTeam(ctx context.Context, projectID, teamID string) error
	ListProjectTeams(ctx context.Context, projectID string) ([]domain.ProjectTeam, error)
}

// TeamRepository is used by the project service to bulk-add team members when assigning a team.
type TeamRepository interface {
	ListMembers(ctx context.Context, teamID string) ([]domain.TeamMember, error)
}

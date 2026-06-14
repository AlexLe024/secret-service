package project

import (
	"context"
	"time"

	"github.com/google/uuid"

	"secret-service/internal/domain"
	"secret-service/internal/errs"
)

type Service struct {
	repo     Repository
	teamRepo TeamRepository
	audit    AuditService
}

func NewService(repo Repository, teamRepo TeamRepository, audit AuditService) *Service {
	return &Service{
		repo:     repo,
		teamRepo: teamRepo,
		audit:    audit,
	}
}

func (s *Service) CreateProject(ctx context.Context, actorUserID, name, description string) (*domain.Project, error) {
	now := time.Now()

	project := &domain.Project{
		ID:          uuid.NewString(),
		Name:        name,
		Description: description,
		CreatedBy:   actorUserID,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := s.repo.CreateProject(ctx, project); err != nil {
		return nil, err
	}

	member := &domain.ProjectMember{
		ID:        uuid.NewString(),
		ProjectID: project.ID,
		UserID:    actorUserID,
		Role:      domain.ProjectRoleAdmin,
		CreatedAt: now,
	}

	if err := s.repo.AddMember(ctx, member); err != nil {
		return nil, err
	}

	projectID := project.ID
	_ = s.audit.Log(ctx, domain.AuditEvent{
		ID:          uuid.NewString(),
		ActorUserID: &actorUserID,
		ProjectID:   &projectID,
		EventType:   domain.AuditProjectCreated,
		CreatedAt:   now,
	})

	return project, nil
}

func (s *Service) AddMember(ctx context.Context, actorUserID, projectID, userID string, role domain.ProjectRole) error {
	actor, err := s.repo.GetMember(ctx, projectID, actorUserID)
	if err != nil {
		return errs.ErrForbidden
	}
	if actor.Role != domain.ProjectRoleAdmin {
		return errs.ErrForbidden
	}

	member := &domain.ProjectMember{
		ID:        uuid.NewString(),
		ProjectID: projectID,
		UserID:    userID,
		Role:      role,
		CreatedAt: time.Now(),
	}

	if err := s.repo.AddMember(ctx, member); err != nil {
		return err
	}

	_ = s.audit.Log(ctx, domain.AuditEvent{
		ID:          uuid.NewString(),
		ActorUserID: &actorUserID,
		ProjectID:   &projectID,
		EventType:   domain.AuditProjectMemberAdd,
		CreatedAt:   time.Now(),
	})

	return nil
}

func (s *Service) RemoveMember(ctx context.Context, actorUserID, projectID, targetUserID string) error {
	actor, err := s.repo.GetMember(ctx, projectID, actorUserID)
	if err != nil {
		return errs.ErrForbidden
	}
	if actor.Role != domain.ProjectRoleAdmin {
		return errs.ErrForbidden
	}
	// Cannot remove yourself — protects from orphaned projects
	if actorUserID == targetUserID {
		return errs.ErrInvalidInput
	}
	return s.repo.RemoveMember(ctx, projectID, targetUserID)
}

func (s *Service) UpdateMemberRole(ctx context.Context, actorUserID, projectID, targetUserID string, role domain.ProjectRole) error {
	actor, err := s.repo.GetMember(ctx, projectID, actorUserID)
	if err != nil {
		return errs.ErrForbidden
	}
	if actor.Role != domain.ProjectRoleAdmin {
		return errs.ErrForbidden
	}
	return s.repo.UpdateMemberRole(ctx, projectID, targetUserID, role)
}

func (s *Service) ListMembers(ctx context.Context, actorUserID, projectID string, limit, offset int) ([]domain.ProjectMember, error) {
	_, err := s.repo.GetMember(ctx, projectID, actorUserID)
	if err != nil {
		return nil, errs.ErrForbidden
	}
	return s.repo.ListMembers(ctx, projectID, limit, offset)
}

func (s *Service) ListUserProjects(ctx context.Context, userID string, limit, offset int) ([]domain.Project, error) {
	return s.repo.ListProjectsByUser(ctx, userID, limit, offset)
}

func (s *Service) GetByID(ctx context.Context, actorUserID, projectID string) (*domain.Project, error) {
	_, err := s.repo.GetMember(ctx, projectID, actorUserID)
	if err != nil {
		return nil, errs.ErrForbidden
	}
	return s.repo.GetProjectByID(ctx, projectID)
}

// AssignTeam links a team to a project and bulk-adds all current team members
// with the given role (defaults to developer). Only project admins can do this.
func (s *Service) AssignTeam(ctx context.Context, actorUserID, projectID, teamID string, role domain.ProjectRole) error {
	actor, err := s.repo.GetMember(ctx, projectID, actorUserID)
	if err != nil {
		return errs.ErrForbidden
	}
	if actor.Role != domain.ProjectRoleAdmin {
		return errs.ErrForbidden
	}

	link := &domain.ProjectTeam{
		ProjectID:  projectID,
		TeamID:     teamID,
		AssignedBy: actorUserID,
		AssignedAt: time.Now(),
	}
	if err := s.repo.AssignTeam(ctx, link); err != nil {
		return err
	}

	// Bulk-add all current team members to the project.
	members, err := s.teamRepo.ListMembers(ctx, teamID)
	if err != nil {
		return err
	}
	for _, m := range members {
		pm := &domain.ProjectMember{
			ID:        uuid.NewString(),
			ProjectID: projectID,
			UserID:    m.UserID,
			Role:      role,
			CreatedAt: time.Now(),
		}
		// Ignore conflict (member already exists); the upsert in AddMember handles it.
		_ = s.repo.AddMember(ctx, pm)
	}

	_ = s.audit.Log(ctx, domain.AuditEvent{
		ID:          uuid.NewString(),
		ActorUserID: &actorUserID,
		ProjectID:   &projectID,
		EventType:   domain.AuditEventType("project_team_assigned"),
		CreatedAt:   time.Now(),
	})

	return nil
}

// UnassignTeam removes a team link from a project (does NOT remove members already added).
func (s *Service) UnassignTeam(ctx context.Context, actorUserID, projectID, teamID string) error {
	actor, err := s.repo.GetMember(ctx, projectID, actorUserID)
	if err != nil {
		return errs.ErrForbidden
	}
	if actor.Role != domain.ProjectRoleAdmin {
		return errs.ErrForbidden
	}
	return s.repo.UnassignTeam(ctx, projectID, teamID)
}

// ListProjectTeams returns the teams assigned to a project.
func (s *Service) ListProjectTeams(ctx context.Context, actorUserID, projectID string) ([]domain.ProjectTeam, error) {
	_, err := s.repo.GetMember(ctx, projectID, actorUserID)
	if err != nil {
		return nil, errs.ErrForbidden
	}
	return s.repo.ListProjectTeams(ctx, projectID)
}

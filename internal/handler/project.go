package handler

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"secret-service/internal/domain"
	"secret-service/internal/dto"
	"secret-service/internal/errs"
	"secret-service/internal/middleware"
)

type ProjectService interface {
	CreateProject(ctx context.Context, actorUserID, name, description string) (*domain.Project, error)
	GetByID(ctx context.Context, actorUserID, projectID string) (*domain.Project, error)
	AddMember(ctx context.Context, actorUserID, projectID, userID string, role domain.ProjectRole) error
	RemoveMember(ctx context.Context, actorUserID, projectID, targetUserID string) error
	UpdateMemberRole(ctx context.Context, actorUserID, projectID, targetUserID string, role domain.ProjectRole) error
	ListMembers(ctx context.Context, actorUserID, projectID string, limit, offset int) ([]domain.ProjectMember, error)
	ListUserProjects(ctx context.Context, userID string, limit, offset int) ([]domain.Project, error)
	AssignTeam(ctx context.Context, actorUserID, projectID, teamID string, role domain.ProjectRole) error
	UnassignTeam(ctx context.Context, actorUserID, projectID, teamID string) error
	ListProjectTeams(ctx context.Context, actorUserID, projectID string) ([]domain.ProjectTeam, error)
}

type ProjectHandler struct {
	svc ProjectService
}

func NewProjectHandler(svc ProjectService) *ProjectHandler {
	return &ProjectHandler{svc: svc}
}

// Get godoc
// @Summary      Get project by ID
// @Tags         projects
// @Produce      json
// @Security     BearerAuth
// @Param        projectID path string true "Project ID"
// @Success      200 {object} domain.Project
// @Failure      401 {object} errorResponse
// @Failure      403 {object} errorResponse
// @Failure      404 {object} errorResponse
// @Router       /projects/{projectID} [get]
func (h *ProjectHandler) Get(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}

	projectID := chi.URLParam(r, "projectID")

	project, err := h.svc.GetByID(r.Context(), userID, projectID)
	if err != nil {
		respondErr(w, err)
		return
	}

	respondJSON(w, http.StatusOK, project)
}

// Create godoc
// @Summary      Create project
// @Tags         projects
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request body dto.CreateProjectRequest true "Project name and description"
// @Success      201 {object} domain.Project
// @Failure      400 {object} errorResponse
// @Failure      401 {object} errorResponse
// @Router       /projects [post]
func (h *ProjectHandler) Create(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}

	var req dto.CreateProjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		respondErr(w, errs.ErrInvalidInput)
		return
	}

	project, err := h.svc.CreateProject(r.Context(), userID, req.Name, req.Description)
	if err != nil {
		respondErr(w, err)
		return
	}

	respondJSON(w, http.StatusCreated, project)
}

// List godoc
// @Summary      List user projects
// @Tags         projects
// @Produce      json
// @Security     BearerAuth
// @Success      200 {array} domain.Project
// @Failure      401 {object} errorResponse
// @Router       /projects [get]
func (h *ProjectHandler) List(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}
	page := dto.ParsePage(r)
	projects, err := h.svc.ListUserProjects(r.Context(), userID, page.Limit, page.Offset)
	if err != nil {
		respondErr(w, err)
		return
	}

	respondJSON(w, http.StatusOK, projects)
}

// ListMembers godoc
// @Summary      List project members
// @Tags         projects
// @Produce      json
// @Security     BearerAuth
// @Param        projectID path string true "Project ID"
// @Success      200 {array} domain.ProjectMember
// @Failure      401 {object} errorResponse
// @Failure      403 {object} errorResponse
// @Router       /projects/{projectID}/members [get]
func (h *ProjectHandler) ListMembers(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}
	projectID := chi.URLParam(r, "projectID")
	page := dto.ParsePage(r)
	members, err := h.svc.ListMembers(r.Context(), userID, projectID, page.Limit, page.Offset)
	if err != nil {
		respondErr(w, err)
		return
	}
	respondJSON(w, http.StatusOK, members)
}

// AddMember godoc
// @Summary      Add member to project
// @Tags         projects
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        projectID path string true "Project ID"
// @Param        request body dto.AddProjectMemberRequest true "User ID and role (admin/manager/developer)"
// @Success      204
// @Failure      400 {object} errorResponse
// @Failure      401 {object} errorResponse
// @Failure      403 {object} errorResponse
// @Router       /projects/{projectID}/members [post]
func (h *ProjectHandler) AddMember(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}

	projectID := chi.URLParam(r, "projectID")

	var req dto.AddProjectMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UserID == "" {
		respondErr(w, errs.ErrInvalidInput)
		return
	}

	role := domain.ProjectRole(req.Role)
	if role != domain.ProjectRoleAdmin && role != domain.ProjectRoleManager && role != domain.ProjectRoleDeveloper {
		respondErr(w, errs.ErrInvalidInput)
		return
	}

	if err := h.svc.AddMember(r.Context(), userID, projectID, req.UserID, role); err != nil {
		respondErr(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// UpdateMemberRole godoc
// @Summary      Change project member role (admin only)
// @Tags         projects
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        projectID path string true "Project ID"
// @Param        userID    path string true "User ID"
// @Param        request   body dto.AddProjectMemberRequest true "New role"
// @Success      204
// @Failure      400 {object} errorResponse
// @Failure      401 {object} errorResponse
// @Failure      403 {object} errorResponse
// @Router       /projects/{projectID}/members/{userID} [patch]
func (h *ProjectHandler) UpdateMemberRole(w http.ResponseWriter, r *http.Request) {
	actorID, ok := middleware.GetUserID(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}
	projectID := chi.URLParam(r, "projectID")
	targetID := chi.URLParam(r, "userID")

	var req dto.AddProjectMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondErr(w, errs.ErrInvalidInput)
		return
	}
	role := domain.ProjectRole(req.Role)
	if role != domain.ProjectRoleAdmin && role != domain.ProjectRoleManager && role != domain.ProjectRoleDeveloper {
		respondErr(w, errs.ErrInvalidInput)
		return
	}
	if err := h.svc.UpdateMemberRole(r.Context(), actorID, projectID, targetID, role); err != nil {
		respondErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RemoveMember godoc
// @Summary      Remove member from project (admin only)
// @Tags         projects
// @Produce      json
// @Security     BearerAuth
// @Param        projectID path string true "Project ID"
// @Param        userID    path string true "User ID"
// @Success      204
// @Failure      400 {object} errorResponse
// @Failure      401 {object} errorResponse
// @Failure      403 {object} errorResponse
// @Failure      404 {object} errorResponse
// @Router       /projects/{projectID}/members/{userID} [delete]
func (h *ProjectHandler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	actorID, ok := middleware.GetUserID(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}
	projectID := chi.URLParam(r, "projectID")
	targetID := chi.URLParam(r, "userID")
	if err := h.svc.RemoveMember(r.Context(), actorID, projectID, targetID); err != nil {
		respondErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// AssignTeam godoc
// @Summary      Assign team to project (bulk-adds all team members)
// @Tags         projects
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        projectID path  string                   true  "Project ID"
// @Param        request   body  dto.AssignTeamRequest    true  "Team ID and optional role"
// @Success      204
// @Failure      400 {object} errorResponse
// @Failure      401 {object} errorResponse
// @Failure      403 {object} errorResponse
// @Router       /projects/{projectID}/teams [post]
func (h *ProjectHandler) AssignTeam(w http.ResponseWriter, r *http.Request) {
	actorID, ok := middleware.GetUserID(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}
	projectID := chi.URLParam(r, "projectID")

	var req dto.AssignTeamRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.TeamID == "" {
		respondErr(w, errs.ErrInvalidInput)
		return
	}

	role := domain.ProjectRole(req.Role)
	if role != domain.ProjectRoleAdmin && role != domain.ProjectRoleManager && role != domain.ProjectRoleDeveloper {
		respondErr(w, errs.ErrInvalidInput)
		return
	}

	if err := h.svc.AssignTeam(r.Context(), actorID, projectID, req.TeamID, role); err != nil {
		respondErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// UnassignTeam godoc
// @Summary      Remove team link from project
// @Tags         projects
// @Produce      json
// @Security     BearerAuth
// @Param        projectID path string true "Project ID"
// @Param        teamID    path string true "Team ID"
// @Success      204
// @Failure      401 {object} errorResponse
// @Failure      403 {object} errorResponse
// @Failure      404 {object} errorResponse
// @Router       /projects/{projectID}/teams/{teamID} [delete]
func (h *ProjectHandler) UnassignTeam(w http.ResponseWriter, r *http.Request) {
	actorID, ok := middleware.GetUserID(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}
	projectID := chi.URLParam(r, "projectID")
	teamID := chi.URLParam(r, "teamID")
	if err := h.svc.UnassignTeam(r.Context(), actorID, projectID, teamID); err != nil {
		respondErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ListTeams godoc
// @Summary      List teams assigned to a project
// @Tags         projects
// @Produce      json
// @Security     BearerAuth
// @Param        projectID path string true "Project ID"
// @Success      200 {array} domain.ProjectTeam
// @Failure      401 {object} errorResponse
// @Failure      403 {object} errorResponse
// @Router       /projects/{projectID}/teams [get]
func (h *ProjectHandler) ListTeams(w http.ResponseWriter, r *http.Request) {
	actorID, ok := middleware.GetUserID(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}
	projectID := chi.URLParam(r, "projectID")
	teams, err := h.svc.ListProjectTeams(r.Context(), actorID, projectID)
	if err != nil {
		respondErr(w, err)
		return
	}
	respondJSON(w, http.StatusOK, teams)
}

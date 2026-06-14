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

type TeamService interface {
	CreateTeam(ctx context.Context, actorUserID, name, description string) (*domain.Team, error)
	ListUserTeams(ctx context.Context, userID string) ([]domain.Team, error)
	AddMember(ctx context.Context, actorUserID, teamID, userID string, role domain.TeamRole) error
	RemoveMember(ctx context.Context, actorUserID, teamID, userID string) error
	ListMembers(ctx context.Context, teamID string) ([]domain.TeamMember, error)
	GetByID(ctx context.Context, teamID string) (*domain.Team, error)
}

type TeamHandler struct {
	svc TeamService
}

func NewTeamHandler(svc TeamService) *TeamHandler {
	return &TeamHandler{svc: svc}
}

// Create godoc
// @Summary      Create team
// @Tags         teams
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request body dto.CreateTeamRequest true "Team name and description"
// @Success      201 {object} domain.Team
// @Failure      400 {object} errorResponse
// @Failure      401 {object} errorResponse
// @Router       /teams [post]
func (h *TeamHandler) Create(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}

	var req dto.CreateTeamRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		respondErr(w, errs.ErrInvalidInput)
		return
	}

	team, err := h.svc.CreateTeam(r.Context(), userID, req.Name, req.Description)
	if err != nil {
		respondErr(w, err)
		return
	}

	respondJSON(w, http.StatusCreated, team)
}

// List godoc
// @Summary      List user teams
// @Tags         teams
// @Produce      json
// @Security     BearerAuth
// @Success      200 {array} domain.Team
// @Failure      401 {object} errorResponse
// @Router       /teams [get]
func (h *TeamHandler) List(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}

	teams, err := h.svc.ListUserTeams(r.Context(), userID)
	if err != nil {
		respondErr(w, err)
		return
	}

	respondJSON(w, http.StatusOK, teams)
}

// AddMember godoc
// @Summary      Add member to team
// @Tags         teams
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        teamID path string true "Team ID"
// @Param        request body dto.AddTeamMemberRequest true "User ID and role (owner/member)"
// @Success      204
// @Failure      400 {object} errorResponse
// @Failure      401 {object} errorResponse
// @Failure      403 {object} errorResponse
// @Router       /teams/{teamID}/members [post]
func (h *TeamHandler) AddMember(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}

	teamID := chi.URLParam(r, "teamID")

	var req dto.AddTeamMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UserID == "" {
		respondErr(w, errs.ErrInvalidInput)
		return
	}

	role := domain.TeamRole(req.Role)
	if role != domain.TeamRoleOwner && role != domain.TeamRoleMember {
		role = domain.TeamRoleMember
	}

	if err := h.svc.AddMember(r.Context(), userID, teamID, req.UserID, role); err != nil {
		respondErr(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// RemoveMember godoc
// @Summary      Remove member from team
// @Tags         teams
// @Produce      json
// @Security     BearerAuth
// @Param        teamID path string true "Team ID"
// @Param        userID path string true "User ID"
// @Success      204
// @Failure      401 {object} errorResponse
// @Failure      403 {object} errorResponse
// @Failure      404 {object} errorResponse
// @Router       /teams/{teamID}/members/{userID} [delete]
func (h *TeamHandler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}

	teamID := chi.URLParam(r, "teamID")
	targetUser := chi.URLParam(r, "userID")

	if err := h.svc.RemoveMember(r.Context(), userID, teamID, targetUser); err != nil {
		respondErr(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ListMembers godoc
// @Summary      List team members
// @Tags         teams
// @Produce      json
// @Security     BearerAuth
// @Param        teamID path string true "Team ID"
// @Success      200 {array} domain.TeamMember
// @Failure      401 {object} errorResponse
// @Router       /teams/{teamID}/members [get]
func (h *TeamHandler) ListMembers(w http.ResponseWriter, r *http.Request) {
	_, ok := middleware.GetUserID(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}

	teamID := chi.URLParam(r, "teamID")

	members, err := h.svc.ListMembers(r.Context(), teamID)
	if err != nil {
		respondErr(w, err)
		return
	}

	respondJSON(w, http.StatusOK, members)
}

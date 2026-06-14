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

type AuthService interface {
	CreateUser(ctx context.Context, email, password string) (*domain.User, error)
	Login(ctx context.Context, email, password string) (string, error)
	GetByID(ctx context.Context, id string) (*domain.User, error)
	ListUsers(ctx context.Context, actorUserID string, limit, offset int) ([]domain.User, error)
	BlockUser(ctx context.Context, actorUserID, targetUserID string) error
	UnblockUser(ctx context.Context, actorUserID, targetUserID string) error
	UpdateDisplayName(ctx context.Context, userID, displayName string) (*domain.User, error)
}

type AuthHandler struct {
	svc AuthService
}

func NewAuthHandler(svc AuthService) *AuthHandler {
	return &AuthHandler{svc: svc}
}

// Register godoc
// @Summary      Register new user
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body dto.CreateUserRequest true "Email and password"
// @Success      201 {object} domain.User
// @Failure      400 {object} errorResponse
// @Failure      409 {object} errorResponse
// @Router       /auth/register [post]
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req dto.CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondErr(w, errs.ErrInvalidInput)
		return
	}
	if req.Email == "" || len(req.Password) < 8 {
		respondErr(w, errs.ErrInvalidInput)
		return
	}
	user, err := h.svc.CreateUser(r.Context(), req.Email, req.Password)
	if err != nil {
		respondErr(w, err)
		return
	}
	respondJSON(w, http.StatusCreated, user)
}

// Login godoc
// @Summary      Login with email and password
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body dto.LoginRequest true "Email and password"
// @Success      200 {object} dto.TokenResponse
// @Failure      401 {object} errorResponse
// @Router       /auth/login [post]
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req dto.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondErr(w, errs.ErrInvalidInput)
		return
	}
	token, err := h.svc.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		respondErr(w, err)
		return
	}
	respondJSON(w, http.StatusOK, dto.TokenResponse{AccessToken: token})
}

// Me godoc
// @Summary      Get current user
// @Tags         auth
// @Produce      json
// @Security     BearerAuth
// @Success      200 {object} domain.User
// @Failure      401 {object} errorResponse
// @Router       /auth/me [get]
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}
	user, err := h.svc.GetByID(r.Context(), userID)
	if err != nil {
		respondErr(w, err)
		return
	}
	respondJSON(w, http.StatusOK, user)
}

// UpdateMe godoc
// @Summary      Update display name
// @Tags         auth
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request body dto.UpdateDisplayNameRequest true "New display name"
// @Success      200 {object} domain.User
// @Failure      400 {object} errorResponse
// @Failure      401 {object} errorResponse
// @Router       /auth/me [patch]
func (h *AuthHandler) UpdateMe(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}
	var req dto.UpdateDisplayNameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondErr(w, errs.ErrInvalidInput)
		return
	}
	user, err := h.svc.UpdateDisplayName(r.Context(), userID, req.DisplayName)
	if err != nil {
		respondErr(w, err)
		return
	}
	respondJSON(w, http.StatusOK, user)
}

// ListUsers godoc
// @Summary      List all users (admin only)
// @Tags         users
// @Produce      json
// @Security     BearerAuth
// @Success      200 {array} domain.User
// @Failure      401 {object} errorResponse
// @Failure      403 {object} errorResponse
// @Router       /users [get]
func (h *AuthHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	actorID, ok := middleware.GetUserID(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}
	page := dto.ParsePage(r)
	users, err := h.svc.ListUsers(r.Context(), actorID, page.Limit, page.Offset)
	if err != nil {
		respondErr(w, err)
		return
	}
	respondJSON(w, http.StatusOK, users)
}

// BlockUser godoc
// @Summary      Block user (admin only)
// @Tags         users
// @Produce      json
// @Security     BearerAuth
// @Param        userID path string true "User ID"
// @Success      204
// @Failure      401 {object} errorResponse
// @Failure      403 {object} errorResponse
// @Router       /users/{userID}/block [post]
func (h *AuthHandler) BlockUser(w http.ResponseWriter, r *http.Request) {
	actorID, ok := middleware.GetUserID(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}
	targetID := chi.URLParam(r, "userID")
	if err := h.svc.BlockUser(r.Context(), actorID, targetID); err != nil {
		respondErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// UnblockUser godoc
// @Summary      Unblock user (admin only)
// @Tags         users
// @Produce      json
// @Security     BearerAuth
// @Param        userID path string true "User ID"
// @Success      204
// @Failure      400 {object} errorResponse
// @Failure      401 {object} errorResponse
// @Failure      403 {object} errorResponse
// @Failure      404 {object} errorResponse
// @Router       /users/{userID}/unblock [post]
func (h *AuthHandler) UnblockUser(w http.ResponseWriter, r *http.Request) {
	actorID, ok := middleware.GetUserID(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}
	targetID := chi.URLParam(r, "userID")
	if err := h.svc.UnblockUser(r.Context(), actorID, targetID); err != nil {
		respondErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

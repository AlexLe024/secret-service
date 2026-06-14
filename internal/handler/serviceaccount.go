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

type ServiceAccountService interface {
	Create(ctx context.Context, actorUserID, projectID, name, description string) (*domain.ServiceAccount, string, error)
	Authenticate(ctx context.Context, saID, rawToken string) (*domain.ServiceAccount, error)
	Revoke(ctx context.Context, actorUserID, saID string) error
	ListByProject(ctx context.Context, actorUserID, projectID string) ([]domain.ServiceAccount, error)
}

type SATokenIssuer interface {
	GenerateForSA(saID, projectID string) (string, error)
}

type ServiceAccountHandler struct {
	svc    ServiceAccountService
	tokens SATokenIssuer
}

func NewServiceAccountHandler(svc ServiceAccountService, tokens SATokenIssuer) *ServiceAccountHandler {
	return &ServiceAccountHandler{svc: svc, tokens: tokens}
}

// Create godoc
// @Summary      Create service account
// @Tags         service-accounts
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        projectID path string true "Project ID"
// @Param        request body dto.CreateServiceAccountRequest true "Service account name and description"
// @Success      201 {object} dto.CreateServiceAccountResponse
// @Failure      400 {object} errorResponse
// @Failure      401 {object} errorResponse
// @Failure      403 {object} errorResponse
// @Router       /projects/{projectID}/service-accounts [post]
func (h *ServiceAccountHandler) Create(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}

	projectID := chi.URLParam(r, "projectID")

	var req dto.CreateServiceAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		respondErr(w, errs.ErrInvalidInput)
		return
	}

	sa, rawToken, err := h.svc.Create(r.Context(), userID, projectID, req.Name, req.Description)
	if err != nil {
		respondErr(w, err)
		return
	}

	respondJSON(w, http.StatusCreated, dto.CreateServiceAccountResponse{
		ID:          sa.ID,
		ProjectID:   sa.ProjectID,
		Name:        sa.Name,
		Description: sa.Description,
		Token:       rawToken,
		Warning:     "Сохраните токен — он показывается только один раз",
	})
}

// Login godoc
// @Summary      Authenticate service account
// @Tags         service-accounts
// @Accept       json
// @Produce      json
// @Param        request body dto.ServiceAccountLoginRequest true "Service account ID and token"
// @Success      200 {object} dto.TokenResponse
// @Failure      400 {object} errorResponse
// @Failure      401 {object} errorResponse
// @Router       /auth/service-login [post]
func (h *ServiceAccountHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req dto.ServiceAccountLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ServiceAccountID == "" || req.Token == "" {
		respondErr(w, errs.ErrInvalidInput)
		return
	}

	sa, err := h.svc.Authenticate(r.Context(), req.ServiceAccountID, req.Token)
	if err != nil {
		respondErr(w, err)
		return
	}

	jwtToken, err := h.tokens.GenerateForSA(sa.ID, sa.ProjectID)
	if err != nil {
		respondErr(w, err)
		return
	}

	respondJSON(w, http.StatusOK, dto.TokenResponse{AccessToken: jwtToken})
}

// Revoke godoc
// @Summary      Revoke service account
// @Tags         service-accounts
// @Produce      json
// @Security     BearerAuth
// @Param        saID path string true "Service account ID"
// @Success      204
// @Failure      401 {object} errorResponse
// @Failure      403 {object} errorResponse
// @Failure      404 {object} errorResponse
// @Router       /service-accounts/{saID}/revoke [post]
func (h *ServiceAccountHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}

	saID := chi.URLParam(r, "saID")

	if err := h.svc.Revoke(r.Context(), userID, saID); err != nil {
		respondErr(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// List godoc
// @Summary      List project service accounts
// @Tags         service-accounts
// @Produce      json
// @Security     BearerAuth
// @Param        projectID path string true "Project ID"
// @Success      200 {array} domain.ServiceAccount
// @Failure      401 {object} errorResponse
// @Router       /projects/{projectID}/service-accounts [get]
func (h *ServiceAccountHandler) List(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}

	projectID := chi.URLParam(r, "projectID")

	accounts, err := h.svc.ListByProject(r.Context(), userID, projectID)
	if err != nil {
		respondErr(w, err)
		return
	}

	respondJSON(w, http.StatusOK, accounts)
}

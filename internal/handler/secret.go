package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"secret-service/internal/domain"
	"secret-service/internal/dto"
	"secret-service/internal/errs"
	"secret-service/internal/middleware"
)

// maxExpiringDays bounds the look-ahead window for the "expiring secrets"
// report so an unbounded ?days= value cannot trigger an excessively wide scan
// or overflow time arithmetic.
const maxExpiringDays = 3650 // ~10 years

type SecretService interface {
	CreateSecret(ctx context.Context, actorUserID, projectID, name, description, value, environment string, tags []string, expiresAt *time.Time) (*domain.Secret, error)
	GetSecret(ctx context.Context, actorUserID, secretID string) (*domain.Secret, error)
	GetSecretValue(ctx context.Context, p domain.Principal, secretID string) (string, error)
	ListSecretsByProject(ctx context.Context, p domain.Principal, projectID string, f domain.SecretFilter, limit, offset int) ([]domain.Secret, error)
	RevokeSecret(ctx context.Context, actorUserID, secretID string) error
	RotateSecret(ctx context.Context, actorUserID, secretID, newValue string) error
	ListVersions(ctx context.Context, p domain.Principal, secretID string) ([]domain.SecretVersion, error)
	RollbackSecret(ctx context.Context, actorUserID, secretID string, version int) error
	ListExpiringSecrets(ctx context.Context, p domain.Principal, projectID string, days int) ([]domain.Secret, error)
}

type AccessService interface {
	GrantAccess(ctx context.Context, actorUserID, projectID, secretID, userID string, expiresAt *time.Time) error
	RevokeAccess(ctx context.Context, actorUserID, projectID, secretID, userID string) error
	ListGrants(ctx context.Context, actorUserID, projectID, secretID string) ([]domain.AccessGrant, error)
}

type SecretHandler struct {
	svc    SecretService
	access AccessService
}

func NewSecretHandler(svc SecretService, access AccessService) *SecretHandler {
	return &SecretHandler{svc: svc, access: access}
}

// Create godoc
// @Summary      Create secret
// @Tags         secrets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        projectID path string true "Project ID"
// @Param        request body dto.CreateSecretRequest true "Secret name, description and value"
// @Success      201 {object} domain.Secret
// @Failure      400 {object} errorResponse
// @Failure      401 {object} errorResponse
// @Failure      403 {object} errorResponse
// @Router       /projects/{projectID}/secrets [post]
func (h *SecretHandler) Create(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}

	projectID := chi.URLParam(r, "projectID")

	var req dto.CreateSecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.Value == "" {
		respondErr(w, errs.ErrInvalidInput)
		return
	}

	secret, err := h.svc.CreateSecret(r.Context(), userID, projectID, req.Name, req.Description, req.Value, req.Environment, req.Tags, req.ExpiresAt)
	if err != nil {
		respondErr(w, err)
		return
	}

	respondJSON(w, http.StatusCreated, secret)
}

// List godoc
// @Summary      List secrets by project
// @Tags         secrets
// @Produce      json
// @Security     BearerAuth
// @Param        projectID path string true "Project ID"
// @Success      200 {array} domain.Secret
// @Failure      401 {object} errorResponse
// @Failure      403 {object} errorResponse
// @Router       /projects/{projectID}/secrets [get]
func (h *SecretHandler) List(w http.ResponseWriter, r *http.Request) {
	principal, ok := middleware.GetPrincipal(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}

	projectID := chi.URLParam(r, "projectID")

	page := dto.ParsePage(r)
	f := parseSecretFilter(r)
	secrets, err := h.svc.ListSecretsByProject(r.Context(), principal, projectID, f, page.Limit, page.Offset)
	if err != nil {
		respondErr(w, err)
		return
	}

	respondJSON(w, http.StatusOK, secrets)
}

// GetValue godoc
// @Summary      Get secret value
// @Tags         secrets
// @Produce      json
// @Security     BearerAuth
// @Param        secretID path string true "Secret ID"
// @Success      200 {object} dto.SecretValueResponse
// @Failure      401 {object} errorResponse
// @Failure      403 {object} errorResponse
// @Failure      404 {object} errorResponse
// @Failure      410 {object} errorResponse
// @Router       /secrets/{secretID}/value [get]
func (h *SecretHandler) GetValue(w http.ResponseWriter, r *http.Request) {
	principal, ok := middleware.GetPrincipal(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}

	secretID := chi.URLParam(r, "secretID")

	value, err := h.svc.GetSecretValue(r.Context(), principal, secretID)
	if err != nil {
		respondErr(w, err)
		return
	}

	respondJSON(w, http.StatusOK, dto.SecretValueResponse{
		SecretID: secretID,
		Value:    value,
	})
}

// Revoke godoc
// @Summary      Revoke secret
// @Tags         secrets
// @Produce      json
// @Security     BearerAuth
// @Param        secretID path string true "Secret ID"
// @Success      204
// @Failure      401 {object} errorResponse
// @Failure      403 {object} errorResponse
// @Failure      404 {object} errorResponse
// @Router       /secrets/{secretID}/revoke [post]
func (h *SecretHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}

	secretID := chi.URLParam(r, "secretID")

	if err := h.svc.RevokeSecret(r.Context(), userID, secretID); err != nil {
		respondErr(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Rotate godoc
// @Summary      Rotate secret value
// @Tags         secrets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        secretID path string true "Secret ID"
// @Param        request body dto.RotateSecretRequest true "New secret value"
// @Success      204
// @Failure      400 {object} errorResponse
// @Failure      401 {object} errorResponse
// @Failure      403 {object} errorResponse
// @Router       /secrets/{secretID}/rotate [post]
func (h *SecretHandler) Rotate(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}

	secretID := chi.URLParam(r, "secretID")

	var req dto.RotateSecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Value == "" {
		respondErr(w, errs.ErrInvalidInput)
		return
	}

	if err := h.svc.RotateSecret(r.Context(), userID, secretID, req.Value); err != nil {
		respondErr(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ListVersions godoc
// @Summary      List secret version history
// @Tags         secrets
// @Produce      json
// @Security     BearerAuth
// @Param        secretID path string true "Secret ID"
// @Success      200 {array} domain.SecretVersion
// @Failure      401 {object} errorResponse
// @Failure      403 {object} errorResponse
// @Failure      404 {object} errorResponse
// @Router       /secrets/{secretID}/versions [get]
func (h *SecretHandler) ListVersions(w http.ResponseWriter, r *http.Request) {
	principal, ok := middleware.GetPrincipal(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}
	secretID := chi.URLParam(r, "secretID")
	versions, err := h.svc.ListVersions(r.Context(), principal, secretID)
	if err != nil {
		respondErr(w, err)
		return
	}
	respondJSON(w, http.StatusOK, versions)
}

// Rollback godoc
// @Summary      Rollback secret to a previous version
// @Tags         secrets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        secretID path string true "Secret ID"
// @Param        request  body dto.RollbackSecretRequest true "Target version number"
// @Success      204
// @Failure      400 {object} errorResponse
// @Failure      401 {object} errorResponse
// @Failure      403 {object} errorResponse
// @Failure      404 {object} errorResponse
// @Router       /secrets/{secretID}/rollback [post]
func (h *SecretHandler) Rollback(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}
	secretID := chi.URLParam(r, "secretID")
	var req dto.RollbackSecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Version < 1 {
		respondErr(w, errs.ErrInvalidInput)
		return
	}
	if err := h.svc.RollbackSecret(r.Context(), userID, secretID, req.Version); err != nil {
		respondErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ListGrants godoc
// @Summary      List access grants for a secret
// @Tags         secrets
// @Produce      json
// @Security     BearerAuth
// @Param        projectID path string true "Project ID"
// @Param        secretID  path string true "Secret ID"
// @Success      200 {array} domain.AccessGrant
// @Failure      401 {object} errorResponse
// @Failure      403 {object} errorResponse
// @Router       /projects/{projectID}/secrets/{secretID}/grants [get]
func (h *SecretHandler) ListGrants(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}
	projectID := chi.URLParam(r, "projectID")
	secretID := chi.URLParam(r, "secretID")
	grants, err := h.access.ListGrants(r.Context(), userID, projectID, secretID)
	if err != nil {
		respondErr(w, err)
		return
	}
	respondJSON(w, http.StatusOK, grants)
}

// GrantAccess godoc
// @Summary      Grant access to secret
// @Tags         secrets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        projectID path string true "Project ID"
// @Param        secretID path string true "Secret ID"
// @Param        request body dto.GrantAccessRequest true "User ID and optional expiration"
// @Success      204
// @Failure      400 {object} errorResponse
// @Failure      401 {object} errorResponse
// @Failure      403 {object} errorResponse
// @Router       /projects/{projectID}/secrets/{secretID}/grants [post]
func (h *SecretHandler) GrantAccess(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}

	projectID := chi.URLParam(r, "projectID")
	secretID := chi.URLParam(r, "secretID")

	var req dto.GrantAccessRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UserID == "" {
		respondErr(w, errs.ErrInvalidInput)
		return
	}

	if err := h.access.GrantAccess(r.Context(), userID, projectID, secretID, req.UserID, req.ExpiresAt); err != nil {
		respondErr(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// RevokeAccess godoc
// @Summary      Revoke user access to secret
// @Tags         secrets
// @Produce      json
// @Security     BearerAuth
// @Param        projectID path string true "Project ID"
// @Param        secretID path string true "Secret ID"
// @Param        userID path string true "User ID"
// @Success      204
// @Failure      401 {object} errorResponse
// @Failure      403 {object} errorResponse
// @Failure      404 {object} errorResponse
// @Router       /projects/{projectID}/secrets/{secretID}/grants/{userID} [delete]
func (h *SecretHandler) RevokeAccess(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}

	projectID := chi.URLParam(r, "projectID")
	secretID := chi.URLParam(r, "secretID")
	targetUserID := chi.URLParam(r, "userID")

	if err := h.access.RevokeAccess(r.Context(), userID, projectID, secretID, targetUserID); err != nil {
		respondErr(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ListExpiring godoc
// @Summary      List secrets expiring soon
// @Tags         secrets
// @Produce      json
// @Security     BearerAuth
// @Param        projectID path  string true  "Project ID"
// @Param        days      query int    false "Number of days to look ahead (default 7)"
// @Success      200 {array} domain.Secret
// @Failure      401 {object} errorResponse
// @Failure      403 {object} errorResponse
// @Router       /projects/{projectID}/secrets/expiring [get]
func (h *SecretHandler) ListExpiring(w http.ResponseWriter, r *http.Request) {
	principal, ok := middleware.GetPrincipal(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}
	projectID := chi.URLParam(r, "projectID")
	days := 7
	if v := r.URL.Query().Get("days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			days = n
			if days > maxExpiringDays {
				days = maxExpiringDays
			}
		}
	}
	secrets, err := h.svc.ListExpiringSecrets(r.Context(), principal, projectID, days)
	if err != nil {
		respondErr(w, err)
		return
	}
	respondJSON(w, http.StatusOK, secrets)
}

// parseSecretFilter reads ?environment=, ?status=, ?name=, ?tag= query params.
// ?tag= may be repeated: ?tag=infra&tag=prod means both tags must be present.
func parseSecretFilter(r *http.Request) domain.SecretFilter {
	var f domain.SecretFilter
	if v := r.URL.Query().Get("environment"); v != "" {
		env := domain.SecretEnvironment(v)
		f.Environment = &env
	}
	if v := r.URL.Query().Get("status"); v != "" {
		st := domain.SecretStatus(v)
		f.Status = &st
	}
	if v := r.URL.Query().Get("name"); v != "" {
		f.Name = &v
	}
	if tags := r.URL.Query()["tag"]; len(tags) > 0 {
		f.Tags = tags
	}
	return f
}

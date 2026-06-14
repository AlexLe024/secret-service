package handler

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"secret-service/internal/domain"
	"secret-service/internal/errs"
	"secret-service/internal/middleware"
)

type AuditService interface {
	ListEvents(ctx context.Context, actorUserID string, f domain.AuditFilter) ([]domain.AuditEvent, error)
}

type AuditHandler struct {
	svc AuditService
}

func NewAuditHandler(svc AuditService) *AuditHandler {
	return &AuditHandler{svc: svc}
}

// ListProjectEvents godoc
// @Summary      List audit events for a project
// @Tags         audit
// @Produce      json
// @Security     BearerAuth
// @Param        projectID   path     string false "Project ID"
// @Param        event_type  query    string false "Filter by event type"
// @Param        actor_user_id query  string false "Filter by actor user ID"
// @Param        secret_id   query   string false "Filter by secret ID"
// @Param        from        query   string false "From timestamp (RFC3339)"
// @Param        to          query   string false "To timestamp (RFC3339)"
// @Param        limit       query   int    false "Max results (default 100, max 500)"
// @Success      200 {array} domain.AuditEvent
// @Failure      401 {object} errorResponse
// @Failure      403 {object} errorResponse
// @Router       /projects/{projectID}/audit/events [get]
func (h *AuditHandler) ListProjectEvents(w http.ResponseWriter, r *http.Request) {
	actorID, ok := middleware.GetUserID(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}

	projectID := chi.URLParam(r, "projectID")
	f := domain.AuditFilter{
		ProjectID: &projectID,
	}
	parseAuditQuery(r, &f)

	events, err := h.svc.ListEvents(r.Context(), actorID, f)
	if err != nil {
		respondErr(w, err)
		return
	}
	respondJSON(w, http.StatusOK, events)
}

// ListAllEvents godoc
// @Summary      List all audit events (admin only)
// @Tags         audit
// @Produce      json
// @Security     BearerAuth
// @Param        project_id    query string false "Filter by project ID"
// @Param        event_type    query string false "Filter by event type"
// @Param        actor_user_id query string false "Filter by actor user ID"
// @Param        secret_id     query string false "Filter by secret ID"
// @Param        from          query string false "From timestamp (RFC3339)"
// @Param        to            query string false "To timestamp (RFC3339)"
// @Param        limit         query int    false "Max results (default 100, max 500)"
// @Success      200 {array} domain.AuditEvent
// @Failure      401 {object} errorResponse
// @Failure      403 {object} errorResponse
// @Router       /audit/events [get]
func (h *AuditHandler) ListAllEvents(w http.ResponseWriter, r *http.Request) {
	actorID, ok := middleware.GetUserID(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}

	var f domain.AuditFilter
	if pid := r.URL.Query().Get("project_id"); pid != "" {
		f.ProjectID = &pid
	}
	parseAuditQuery(r, &f)

	events, err := h.svc.ListEvents(r.Context(), actorID, f)
	if err != nil {
		respondErr(w, err)
		return
	}
	respondJSON(w, http.StatusOK, events)
}

func parseAuditQuery(r *http.Request, f *domain.AuditFilter) {
	q := r.URL.Query()

	if v := q.Get("event_type"); v != "" {
		et := domain.AuditEventType(v)
		f.EventType = &et
	}
	if v := q.Get("actor_user_id"); v != "" {
		f.ActorUserID = &v
	}
	if v := q.Get("secret_id"); v != "" {
		f.SecretID = &v
	}
	if v := q.Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.From = &t
		}
	}
	if v := q.Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.To = &t
		}
	}
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.Limit = n
		}
	}
}

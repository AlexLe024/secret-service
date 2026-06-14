package handler

import (
	"context"
	"net/http"

	"secret-service/internal/dto"
	"secret-service/internal/errs"
	"secret-service/internal/middleware"
)

type AdminStatsService interface {
	GetStats(ctx context.Context, actorUserID string) (*dto.StatsResponse, error)
}

type AdminHandler struct {
	svc AdminStatsService
}

func NewAdminHandler(svc AdminStatsService) *AdminHandler {
	return &AdminHandler{svc: svc}
}

// GetStats godoc
// @Summary      Platform-wide statistics (admin only)
// @Tags         admin
// @Produce      json
// @Security     BearerAuth
// @Success      200 {object} dto.StatsResponse
// @Failure      401 {object} errorResponse
// @Failure      403 {object} errorResponse
// @Router       /admin/stats [get]
func (h *AdminHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	actorID, ok := middleware.GetUserID(r)
	if !ok {
		respondErr(w, errs.ErrUnauthorized)
		return
	}
	stats, err := h.svc.GetStats(r.Context(), actorID)
	if err != nil {
		respondErr(w, err)
		return
	}
	respondJSON(w, http.StatusOK, stats)
}

package http

import (
	"context"
	stdhttp "net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jmoiron/sqlx"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	httpswagger "github.com/swaggo/http-swagger"
	"golang.org/x/time/rate"

	"secret-service/internal/handler"
	"secret-service/internal/middleware"
)

func NewRouter(
	authH *handler.AuthHandler,
	projectH *handler.ProjectHandler,
	secretH *handler.SecretHandler,
	saH *handler.ServiceAccountHandler,
	teamH *handler.TeamHandler,
	auditH *handler.AuditHandler,
	adminH *handler.AdminHandler,
	db *sqlx.DB,
	tokenParser middleware.TokenParser,
	principalValidator middleware.PrincipalValidator,
) stdhttp.Handler {
	r := chi.NewRouter()

	r.Use(middleware.Recovery)
	r.Use(middleware.RequestID)
	r.Use(middleware.Logging)
	r.Use(middleware.Metrics)

	r.Get("/health", func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		if err := db.PingContext(ctx); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(stdhttp.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"unavailable","db":"unreachable"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(stdhttp.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","db":"reachable"}`))
	})

	r.Get("/metrics", promhttp.Handler().ServeHTTP)

	// Swagger UI
	r.Get("/swagger/*", httpswagger.Handler(
		httpswagger.URL("/swagger/doc.json"),
	))

	// Public auth endpoints — rate limited to 5 req/s burst 10 per IP.
	// Tests set AUTH_RATE_LIMIT_DISABLE=1 to bypass throttling without affecting prod defaults.
	limit, burst := rate.Limit(5), 10
	if os.Getenv("AUTH_RATE_LIMIT_DISABLE") == "1" {
		limit, burst = rate.Limit(10000), 10000
	}
	// Only trust X-Forwarded-For when explicitly deployed behind a trusted proxy,
	// otherwise the header is spoofable and would let clients evade the limit.
	trustProxy := os.Getenv("TRUST_PROXY") == "1"
	authLimiter := middleware.NewRateLimiter(limit, burst, trustProxy)
	r.Group(func(r chi.Router) {
		r.Use(authLimiter.Limit)
		r.Post("/api/v1/auth/register", authH.Register)
		r.Post("/api/v1/auth/login", authH.Login)
		r.Post("/api/v1/auth/service-login", saH.Login)
	})

	// Protected
	r.Group(func(r chi.Router) {
		r.Use(middleware.Auth(tokenParser, principalValidator))

		// Current user
		r.Get("/api/v1/auth/me", authH.Me)
		r.Patch("/api/v1/auth/me", authH.UpdateMe)

		// Users
		r.Get("/api/v1/users", authH.ListUsers)
		r.Post("/api/v1/users/{userID}/block", authH.BlockUser)
		r.Post("/api/v1/users/{userID}/unblock", authH.UnblockUser)

		// Teams
		r.Post("/api/v1/teams", teamH.Create)
		r.Get("/api/v1/teams", teamH.List)
		r.Post("/api/v1/teams/{teamID}/members", teamH.AddMember)
		r.Delete("/api/v1/teams/{teamID}/members/{userID}", teamH.RemoveMember)
		r.Get("/api/v1/teams/{teamID}/members", teamH.ListMembers)

		// Projects
		r.Post("/api/v1/projects", projectH.Create)
		r.Get("/api/v1/projects", projectH.List)
		r.Get("/api/v1/projects/{projectID}", projectH.Get)
		r.Get("/api/v1/projects/{projectID}/members", projectH.ListMembers)
		r.Post("/api/v1/projects/{projectID}/members", projectH.AddMember)
		r.Patch("/api/v1/projects/{projectID}/members/{userID}", projectH.UpdateMemberRole)
		r.Delete("/api/v1/projects/{projectID}/members/{userID}", projectH.RemoveMember)
		r.Post("/api/v1/projects/{projectID}/teams", projectH.AssignTeam)
		r.Delete("/api/v1/projects/{projectID}/teams/{teamID}", projectH.UnassignTeam)
		r.Get("/api/v1/projects/{projectID}/teams", projectH.ListTeams)

		// Secrets
		r.Post("/api/v1/projects/{projectID}/secrets", secretH.Create)
		r.Get("/api/v1/projects/{projectID}/secrets", secretH.List)
		r.Get("/api/v1/projects/{projectID}/secrets/expiring", secretH.ListExpiring)
		r.Get("/api/v1/secrets/{secretID}/value", secretH.GetValue)
		r.Get("/api/v1/secrets/{secretID}/versions", secretH.ListVersions)
		r.Post("/api/v1/secrets/{secretID}/revoke", secretH.Revoke)
		r.Post("/api/v1/secrets/{secretID}/rotate", secretH.Rotate)
		r.Post("/api/v1/secrets/{secretID}/rollback", secretH.Rollback)

		// Access grants
		r.Get("/api/v1/projects/{projectID}/secrets/{secretID}/grants", secretH.ListGrants)
		r.Post("/api/v1/projects/{projectID}/secrets/{secretID}/grants", secretH.GrantAccess)
		r.Delete("/api/v1/projects/{projectID}/secrets/{secretID}/grants/{userID}", secretH.RevokeAccess)

		// Service accounts
		r.Post("/api/v1/projects/{projectID}/service-accounts", saH.Create)
		r.Get("/api/v1/projects/{projectID}/service-accounts", saH.List)
		r.Post("/api/v1/service-accounts/{saID}/revoke", saH.Revoke)

		// Audit
		r.Get("/api/v1/projects/{projectID}/audit/events", auditH.ListProjectEvents)
		r.Get("/api/v1/audit/events", auditH.ListAllEvents)

		// Admin
		r.Get("/api/v1/admin/stats", adminH.GetStats)
	})

	return r
}

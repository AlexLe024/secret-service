package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"secret-service/internal/access"
	"secret-service/internal/admin"
	"secret-service/internal/audit"
	"secret-service/internal/auth"
	"secret-service/internal/authz"
	"secret-service/internal/crypto"
	"secret-service/internal/handler"
	apphttp "secret-service/internal/http"
	"secret-service/internal/project"
	"secret-service/internal/secret"
	"secret-service/internal/serviceaccount"
	"secret-service/internal/storage"
	"secret-service/internal/team"
	"secret-service/internal/token"
)

type TestEnv struct {
	Server    *httptest.Server
	DB        *sqlx.DB
	Container testcontainers.Container
}

func NewTestEnv(t *testing.T) *TestEnv {
	t.Helper()
	ctx := context.Background()

	// Поднимаем PostgreSQL в контейнере
	pgContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("get connection string: %v", err)
	}

	db, err := sqlx.Connect("postgres", connStr)
	if err != nil {
		t.Fatalf("connect to test db: %v", err)
	}

	// Применяем миграции
	applyMigrations(t, db)

	// Собираем сервисы
	// Repositories
	userRepo := storage.NewUserRepo(db)
	projectRepo := storage.NewProjectRepo(db)
	secretRepo := storage.NewSecretRepo(db)
	accessRepo := storage.NewAccessGrantRepo(db)
	auditRepo := storage.NewAuditRepo(db)
	saRepo := storage.NewServiceAccountRepo(db)
	teamRepo := storage.NewTeamRepo(db)

	// Infrastructure
	aesKey := make([]byte, 32) // all-zero key is sufficient for tests
	cryptoSvc, _ := crypto.NewAESGCMService(aesKey)
	jwtProvider := token.NewJWTProvider("test-jwt-secret-for-testing-only")
	bcryptHasher := auth.NewBcryptHasher()

	// Services
	auditSvc := audit.NewService(auditRepo, userRepo, projectRepo)
	authSvc := auth.NewService(userRepo, bcryptHasher, jwtProvider, auditSvc)
	projectSvc := project.NewService(projectRepo, teamRepo, auditSvc)
	accessSvc := access.NewService(accessRepo, projectRepo, secretRepo, auditSvc)
	secretSvc := secret.NewService(secretRepo, projectRepo, cryptoSvc, accessSvc, auditSvc)
	saSvc := serviceaccount.NewService(saRepo, projectRepo, auditSvc)
	teamSvc := team.NewService(teamRepo, auditSvc)

	// Handlers
	statsRepo := storage.NewStatsRepo(db)
	adminSvc := admin.NewService(statsRepo, userRepo)
	authHandler := handler.NewAuthHandler(authSvc)
	projectHandler := handler.NewProjectHandler(projectSvc)
	secretHandler := handler.NewSecretHandler(secretSvc, accessSvc)
	saHandler := handler.NewServiceAccountHandler(saSvc, jwtProvider)
	teamHandler := handler.NewTeamHandler(teamSvc)
	auditHandler := handler.NewAuditHandler(auditSvc)
	adminHandler := handler.NewAdminHandler(adminSvc)

	principalValidator := authz.NewValidator(userRepo, saRepo)
	router := apphttp.NewRouter(
		authHandler, projectHandler, secretHandler, saHandler, teamHandler,
		auditHandler, adminHandler, db, jwtProvider, principalValidator,
	)
	srv := httptest.NewServer(router)

	t.Cleanup(func() {
		srv.Close()
		db.Close()
		pgContainer.Terminate(ctx)
	})

	return &TestEnv{
		Server:    srv,
		DB:        db,
		Container: pgContainer,
	}
}

func applyMigrations(t *testing.T, db *sqlx.DB) {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	migrations := []string{
		"001_init.sql",
		"002_service_accounts.sql",
		"003_user_fields.sql",
		"004_teams.sql",
		"005_user_admin.sql",
		"006_secret_ttl.sql",
		"007_secret_environment.sql",
		"008_secret_tags.sql",
		"009_project_teams.sql",
	}

	for _, name := range migrations {
		path := filepath.Join(wd, "..", "..", "migrations", name)
		sql, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read migration %s: %v", name, err)
		}
		if _, err := db.Exec(string(sql)); err != nil {
			t.Fatalf("apply migration %s: %v", name, err)
		}
	}
}

// --- HTTP helpers ---

func (e *TestEnv) Post(path string, body any, token string) *http.Response {
	return e.request(http.MethodPost, path, body, token)
}

func (e *TestEnv) Get(path string, token string) *http.Response {
	return e.request(http.MethodGet, path, nil, token)
}

func (e *TestEnv) Delete(path string, token string) *http.Response {
	return e.request(http.MethodDelete, path, nil, token)
}

func (e *TestEnv) request(method, path string, body any, tok string) *http.Response {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}

	req, _ := http.NewRequest(method, e.Server.URL+path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(fmt.Sprintf("request failed: %v", err))
	}
	return resp
}

func DecodeJSON(t *testing.T, resp *http.Response, dst any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

// RegisterAndLogin — вспомогательный метод для получения токена в тестах
func (e *TestEnv) RegisterAndLogin(t *testing.T, email, password string) string {
	t.Helper()

	resp := e.Post("/api/v1/auth/register", map[string]string{
		"email": email, "password": password,
	}, "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register failed: status %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = e.Post("/api/v1/auth/login", map[string]string{
		"email": email, "password": password,
	}, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login failed: status %d", resp.StatusCode)
	}

	var result map[string]string
	DecodeJSON(t, resp, &result)
	return result["access_token"]
}

func userIDFromToken(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid jwt format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode jwt payload: %v", err)
	}
	var claims struct {
		UserID string `json:"user_id"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal jwt payload: %v", err)
	}
	return claims.UserID
}

package main

import (
	"context"
	"encoding/hex"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	_ "secret-service/docs"
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

// @title           Secret Service API
// @version         1.0
// @description     Centralized API key storage and management service for development teams.
// @host            localhost:8080
// @BasePath        /api/v1
// @securityDefinitions.apikey BearerAuth
// @in              header
// @name            Authorization

func main() {
	// JSON structured logging; switch to text handler for local dev if needed
	logLevel := slog.LevelInfo
	if getEnv("LOG_LEVEL", "") == "debug" {
		logLevel = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})))

	dbHost := getEnv("DB_HOST", "localhost")
	dbPort := getEnvInt("DB_PORT", 5432)
	dbUser := getEnv("DB_USER", "postgres")
	dbPass := getEnv("DB_PASSWORD", "postgres")
	dbName := getEnv("DB_NAME", "secret_service")
	dbSSL := getEnv("DB_SSLMODE", "disable")

	jwtSecret := getEnv("JWT_SECRET", "")
	if len(jwtSecret) < 32 {
		slog.Error("JWT_SECRET env variable is required (minimum 32 characters)")
		os.Exit(1)
	}

	aesKeyHex := getEnv("AES_KEY_HEX", "")
	if aesKeyHex == "" {
		slog.Error("AES_KEY_HEX env variable is required (64 hex chars = 32 bytes)")
		os.Exit(1)
	}
	aesKey, err := hex.DecodeString(aesKeyHex)
	if err != nil || len(aesKey) != 32 {
		slog.Error("AES_KEY_HEX must be exactly 64 hex characters (32 bytes)")
		os.Exit(1)
	}

	addr := getEnv("ADDR", ":8080")

	db, err := storage.New(storage.Config{
		Host: dbHost, Port: dbPort, User: dbUser,
		Password: dbPass, DBName: dbName, SSLMode: dbSSL,
	})
	if err != nil {
		slog.Error("db connect failed", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		slog.Error("db ping failed", "error", err)
		os.Exit(1)
	}
	slog.Info("connected to PostgreSQL")

	// Auto-migrations
	migrationsDir := getEnv("MIGRATIONS_DIR", "./migrations")
	migrFS := os.DirFS(migrationsDir)
	migrCtx, migrCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer migrCancel()
	if err := storage.RunMigrations(migrCtx, db, migrFS); err != nil {
		slog.Error("migrations failed", "error", err)
		os.Exit(1)
	}
	slog.Info("migrations up to date")

	// Repositories
	userRepo := storage.NewUserRepo(db)
	projectRepo := storage.NewProjectRepo(db)
	secretRepo := storage.NewSecretRepo(db)
	accessRepo := storage.NewAccessGrantRepo(db)
	auditRepo := storage.NewAuditRepo(db)
	saRepo := storage.NewServiceAccountRepo(db)
	teamRepo := storage.NewTeamRepo(db)
	statsRepo := storage.NewStatsRepo(db)

	// Infrastructure
	cryptoSvc, err := crypto.NewAESGCMService(aesKey)
	if err != nil {
		slog.Error("crypto init failed", "error", err)
		os.Exit(1)
	}
	jwtProvider := token.NewJWTProvider(jwtSecret)
	bcryptHasher := auth.NewBcryptHasher()
	principalValidator := authz.NewValidator(userRepo, saRepo)

	// Domain services
	auditSvc := audit.NewService(auditRepo, userRepo, projectRepo)
	authSvc := auth.NewService(userRepo, bcryptHasher, jwtProvider, auditSvc)
	projectSvc := project.NewService(projectRepo, teamRepo, auditSvc)
	accessSvc := access.NewService(accessRepo, projectRepo, secretRepo, auditSvc)
	secretSvc := secret.NewService(secretRepo, projectRepo, cryptoSvc, accessSvc, auditSvc)
	saSvc := serviceaccount.NewService(saRepo, projectRepo, auditSvc)
	teamSvc := team.NewService(teamRepo, auditSvc)
	adminSvc := admin.NewService(statsRepo, userRepo)

	// Handlers
	authHandler := handler.NewAuthHandler(authSvc)
	projectHandler := handler.NewProjectHandler(projectSvc)
	secretHandler := handler.NewSecretHandler(secretSvc, accessSvc)
	saHandler := handler.NewServiceAccountHandler(saSvc, jwtProvider)
	teamHandler := handler.NewTeamHandler(teamSvc)
	auditHandler := handler.NewAuditHandler(auditSvc)
	adminHandler := handler.NewAdminHandler(adminSvc)

	router := apphttp.NewRouter(authHandler, projectHandler, secretHandler, saHandler, teamHandler, auditHandler, adminHandler, db, jwtProvider, principalValidator)

	srv := &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		slog.Info("server started", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	<-quit
	slog.Info("shutting down server...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("server forced shutdown", "error", err)
		os.Exit(1)
	}
	slog.Info("server stopped")
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

# Secret Service — Technical Documentation

This document drills into the implementation details that don't fit in the README. For setup and feature overview, start with the [README](./README.md). For a discussion of trade-offs and design decisions, see the [Case Study](./CASE_STUDY.md). For a list of known security fixes applied before the public release, see [SECURITY.md](./SECURITY.md).

---

## Table of contents

1. [Architecture](#1-architecture)
2. [Database schema](#2-database-schema)
3. [Configuration](#3-configuration)
4. [Authentication and authorization](#4-authentication-and-authorization)
5. [HTTP API reference](#5-http-api-reference)
6. [CLI client](#6-cli-client)
7. [Service layer — what each service does](#7-service-layer--what-each-service-does)
8. [Middleware stack](#8-middleware-stack)
9. [Cryptography](#9-cryptography)
10. [Audit log events](#10-audit-log-events)
11. [Permissions matrix](#11-permissions-matrix)
12. [Production deployment notes](#12-production-deployment-notes)

---

## 1. Architecture

The service follows a strict layered architecture. Each layer depends only on the interfaces of the next — no upward dependencies, no circular imports.

```
HTTP request
    │
    ▼
[Recovery] → [RequestID] → [Logging] → [Metrics]
    │
    ▼
[Auth middleware] — parses JWT, extracts Principal (user or service account)
    │
    ▼
Handler (chi router)
    │
    ▼
Service (business logic, permission checks, audit emission)
    │
    ▼
Repository interface
    │
    ▼
storage.* (sqlx + PostgreSQL)
```

### Source tree

```
cmd/
  server/main.go      Server entry point — wires everything together
  cli/main.go         CLI entry point

internal/
  domain/             Pure Go structs (User, Project, Secret, Principal)
  dto/                Request/response objects (HTTP layer only)
  errs/               Centralized sentinel errors
  crypto/             AES-256-GCM encryption service
  token/              JWT issue + parse
  auth/               User registration, login, password hashing
  project/            Projects + RBAC + team assignment
  secret/             Secrets + versioning + rotation
  access/             Time-bound access grants
  serviceaccount/     Machine-to-machine accounts
  team/               User groups for bulk project assignment
  audit/              Audit log writes
  admin/              Platform-level stats (global-admin only)
  storage/            sqlx-backed repository implementations
  handler/            HTTP handlers (chi)
  http/               Router + middleware registration
  middleware/         Auth, Logging, RequestID, Recovery, Metrics, RateLimit

migrations/           SQL migrations, auto-applied on startup
docs/                 Generated Swagger JSON/YAML
tests/
  unit/               Crypto and JWT tests
  integration/        Full HTTP → DB tests via testcontainers-go
```

### Design principles

- **Layered, not "clean".** No use-case package, no per-layer DTO mapping ceremony. Domain → service → repository → handler is enough at this scale.
- **No magic.** No codegen, no dependency injection container. Constructor injection from `main.go` — read top to bottom and you understand the dependency graph.
- **Testability first.** Integration tests run against real PostgreSQL via testcontainers-go. No mock databases.
- **Graceful shutdown.** SIGINT/SIGTERM handled with a 10-second drain.

---

## 2. Database schema

PostgreSQL 14+. All identifiers are TEXT (UUID-shaped), all timestamps `TIMESTAMPTZ DEFAULT NOW()`.

| Table | Purpose | Key columns |
|---|---|---|
| `users` | Global user accounts | `email UNIQUE`, `password_hash`, `is_blocked`, `is_admin` |
| `projects` | Top-level grouping for secrets | `name`, `created_by FK→users` |
| `project_members` | RBAC at project level | `(project_id, user_id) UNIQUE`, `role CHECK IN ('admin','manager','developer')` |
| `teams` | User groups for bulk assignment | `name`, `created_by FK→users` |
| `team_members` | Team membership | `(team_id, user_id) UNIQUE` |
| `project_teams` | Team-to-project bulk assignment | `(project_id, team_id) UNIQUE`, `role` |
| `secrets` | Secret metadata (no values) | `(project_id, name) UNIQUE`, `status CHECK IN ('active','revoked')`, `environment`, `tags TEXT[]`, `expires_at` |
| `secret_versions` | Encrypted values, versioned | `(secret_id, version) UNIQUE`, `encrypted_value BYTEA`, `nonce BYTEA`, `is_current BOOLEAN` |
| `access_grants` | Time-bound read access | `(secret_id, user_id) UNIQUE`, `expires_at` |
| `service_accounts` | Machine-to-machine credentials | `(project_id, name) UNIQUE`, `token_hash`, `status` |
| `audit_events` | Append-only event log | `actor_user_id`, `project_id`, `secret_id`, `event_type`, `metadata JSONB` |
| `schema_migrations` | Migration tracking | applied internally |

Key indexes:
- `secret_versions`: partial index on `(secret_id) WHERE is_current = TRUE` — makes "fetch current value" O(1)
- `audit_events`: composite indexes on `(project_id, created_at DESC)` and `(secret_id, created_at DESC)` for paginated listing

Migrations live in `/migrations` and are applied automatically on startup. Order matters — `001_init.sql` builds the base schema; later files add teams, environments, tags, project_teams, and TTLs.

---

## 3. Configuration

All configuration via environment variables. No config files.

| Variable | Required | Default | Description |
|---|---|---|---|
| `DB_HOST` | no | `localhost` | PostgreSQL host |
| `DB_PORT` | no | `5432` | PostgreSQL port |
| `DB_USER` | no | `postgres` | PostgreSQL user |
| `DB_PASSWORD` | no | `postgres` | PostgreSQL password |
| `DB_NAME` | no | `secret_service` | Database name |
| `DB_SSLMODE` | no | `disable` | One of `disable`, `require`, `verify-ca`, `verify-full` |
| `AES_KEY_HEX` | **yes** | — | 32-byte AES-256 key as 64 hex chars. Generate with `openssl rand -hex 32`. |
| `JWT_SECRET` | **yes** | — | JWT signing secret, minimum 32 characters |
| `ADDR` | no | `:8080` | Server bind address |
| `LOG_LEVEL` | no | `info` | One of `debug`, `info`, `warn`, `error` |
| `MIGRATIONS_DIR` | no | `./migrations` | Path to SQL migration files |
| `TRUST_PROXY` | no | `0` | Set to `1` to honor `X-Forwarded-For` from a known reverse proxy |

The server validates all required variables on startup and exits with a clear error if any is missing or malformed.

---

## 4. Authentication and authorization

### Principal abstraction

After the auth middleware parses a JWT, it builds a `domain.Principal` and puts it in the request context. Every handler reads the principal — no handler ever reads a raw user ID directly.

```go
type Principal struct {
    Kind      PrincipalKind // "user" or "service_account"
    UserID    string        // only set when Kind == "user"
    SAID      string        // only set when Kind == "service_account"
    ProjectID string        // scope for service accounts
    IsAdmin   bool          // global admin flag, users only
}
```

This separation is enforced — calling `Principal.GetUserID()` on a service-account principal returns the empty string, so any handler that requires a user is automatically protected against an SA token sneaking through.

### User tokens

- Algorithm: HS256
- TTL: 24 hours
- Required claims: `exp`, `iss`, `aud`, `sub: "user"`, `user_id`, `is_admin`
- Validated on every request: token must be signed with HS256, must have `exp`, must match issuer and audience

### Service account tokens

- Algorithm: HS256
- TTL: 1 hour (intentionally short — these are machine credentials)
- Required claims: `exp`, `iss`, `aud`, `sub: "service_account"`, `user_id` (= SA ID), `project_id`

### Per-request revocation

When the auth middleware validates a token, it also looks up the actor's current status in the database:
- If a user is blocked, the JWT is rejected even though it hasn't expired
- If a service account is revoked, the JWT is rejected immediately

This adds one database query per authenticated request. For higher-throughput deployments, see the caching note in [Production deployment notes](#12-production-deployment-notes).

### Access check chain for `GET /secrets/{secretID}/value`

```
1. Secret exists, status = 'active', not expired
2. Caller is a user:
   a. User is a member of the parent project        → allow
   b. Active access_grant exists for (secret, user) → allow
   c. Otherwise                                     → deny + audit secret_read_denied
3. Caller is a service account:
   a. SA is bound to the secret's project           → allow
   b. Otherwise                                     → deny + audit secret_read_denied
```

---

## 5. HTTP API reference

Base URL: `http://localhost:8080`. All requests require `Authorization: Bearer <token>` unless noted. The Swagger UI at `/swagger/` is always the authoritative reference; this section is a navigator.

### Auth

| Method | Path | Notes |
|---|---|---|
| POST | `/api/v1/auth/register` | Public, rate-limited. First registered user becomes global admin. |
| POST | `/api/v1/auth/login` | Public, rate-limited. Returns access token. |
| POST | `/api/v1/auth/service-login` | Public, rate-limited. Service account auth via `(SA_ID, token)`. |
| GET | `/api/v1/auth/me` | Current user info. |
| PATCH | `/api/v1/auth/me` | Update display name. |

### Users (global admin only)

| Method | Path | Notes |
|---|---|---|
| GET | `/api/v1/users` | List all users. |
| POST | `/api/v1/users/{userID}/block` | Block a user. Blocked users can't authenticate. |
| POST | `/api/v1/users/{userID}/unblock` | Unblock a user. |

### Projects

| Method | Path | Notes |
|---|---|---|
| POST | `/api/v1/projects` | Creator becomes project admin. |
| GET | `/api/v1/projects` | Projects the caller is a member of. |
| GET | `/api/v1/projects/{projectID}` | Project detail. |
| GET / POST / PATCH / DELETE | `/api/v1/projects/{projectID}/members[/{userID}]` | Member CRUD; project admin only. |
| GET / POST / DELETE | `/api/v1/projects/{projectID}/teams[/{teamID}]` | Team assignment; project admin only. |

### Teams

| Method | Path | Notes |
|---|---|---|
| POST / GET | `/api/v1/teams` | Create team, list caller's teams. |
| GET / POST / DELETE | `/api/v1/teams/{teamID}/members[/{userID}]` | Manage team membership. |

### Secrets

| Method | Path | Notes |
|---|---|---|
| POST | `/api/v1/projects/{projectID}/secrets` | Create secret; admin/manager only. |
| GET | `/api/v1/projects/{projectID}/secrets` | List with `environment` and `tags` filters, paginated. |
| GET | `/api/v1/secrets/{secretID}/value` | Decrypted value; audited. |
| POST | `/api/v1/secrets/{secretID}/revoke` | Mark secret as revoked; reads are denied. |
| POST | `/api/v1/secrets/{secretID}/rotate` | Creates a new version, sets it as current. |
| GET | `/api/v1/secrets/{secretID}/versions` | Version history. |
| POST | `/api/v1/secrets/{secretID}/rollback` | Set a previous version as current. |
| GET | `/api/v1/projects/{projectID}/secrets/expiring` | Secrets expiring within N days (capped at 3650). |
| GET / POST / DELETE | `/api/v1/projects/{projectID}/secrets/{secretID}/grants[/{userID}]` | Time-bound access grants. |

### Service accounts

| Method | Path | Notes |
|---|---|---|
| POST | `/api/v1/projects/{projectID}/service-accounts` | Returns plaintext token *once*. |
| GET | `/api/v1/projects/{projectID}/service-accounts` | List SAs in project; admin/manager only. |
| POST | `/api/v1/service-accounts/{saID}/revoke` | Revoke an SA. Existing tokens are rejected at the next request. |

### Audit

| Method | Path | Notes |
|---|---|---|
| GET | `/api/v1/projects/{projectID}/audit/events` | Project-scoped audit, filterable by event type and date range. |
| GET | `/api/v1/audit/events` | Global audit log; global admin only. |

### System

| Method | Path | Notes |
|---|---|---|
| GET | `/health` | Liveness probe. |
| GET | `/metrics` | Prometheus metrics. |
| GET | `/swagger/*` | Interactive API documentation. |

---

## 6. CLI client

The CLI lives in `cmd/cli` and is built with `cobra`. It maintains session state in `~/.secret-service/session.json` (mode `0600`).

```bash
ss login --email alice@example.com           # prompts for password, saves session
ss logout                                    # clears session
ss whoami                                    # current user

ss projects list
ss projects create --name "my-app"

ss secrets list --project my-app --env prod
ss secrets set   --project my-app --name DATABASE_URL --value "postgres://..."
ss secrets get   --project my-app --name DATABASE_URL
ss secrets rotate --project my-app --name DATABASE_URL --value "postgres://..."

ss run --project my-app --env prod -- ./deploy.sh
# Loads all secrets in the project/env as env vars and execs the command.
# Useful in CI pipelines.
```

---

## 7. Service layer — what each service does

Each service receives its dependencies (repositories, helper services) through interfaces. Handlers only call service methods — never repositories directly.

### `auth.Service`
- `Register` — hashes password (bcrypt, cost 10), enforces password length 8–72 bytes, makes the first user a global admin, emits `user_registered`.
- `Login` — looks up user, constant-time bcrypt comparison (uses `DummyCompare` if user doesn't exist to defeat timing-based enumeration), checks `is_blocked`, issues JWT, emits `user_logged_in`.
- `BlockUser` / `UnblockUser` — global-admin only, can't act on yourself.

### `project.Service`
- `Create` — creates project + adds creator as `admin` in `project_members`.
- `AssignTeam` — project admin only, upserts team members into the project at the given role; rejects unknown roles.
- `AddMember` / `RemoveMember` / `UpdateMemberRole` — admin only.

### `secret.Service`
- `Create` — admin/manager only, encrypts value (AES-256-GCM), creates secret + version 1 (`is_current=true`).
- `GetValue` — runs the access check chain (see §4), decrypts current version, emits `secret_read` or `secret_read_denied`.
- `Rotate` — clears `is_current` on existing versions, creates a new version with `is_current=true`.
- `Rollback` — atomic UPDATE that sets `is_current = (version = $target)` in a single statement.
- `ListExpiring` — `WHERE expires_at <= NOW() + interval` (the previous `expires_at > NOW()` filter was a bug — already-expired secrets were silently hidden).

### `access.Service`
- `CanRead` — checks project membership or active grant.
- `Grant` / `Revoke` — admin/manager only. Verifies the secret actually belongs to the URL's project (defends against IDOR — see [SECURITY.md](./SECURITY.md)).

### `serviceaccount.Service`
- `Create` — generates a random token, stores its bcrypt hash, returns the plaintext exactly once.
- `Authenticate` — looks up SA, bcrypt-compares token, checks `status='active'`, returns SA-scoped JWT.

### `team.Service`
- `Create`, `AddMember`, `RemoveMember`, `ListMembers` — straightforward CRUD with `actor` checks.

### `audit.Service`
- `Log` — central emission point; logs failures to stderr but never blocks the calling operation.

---

## 8. Middleware stack

Applied in order:

| Middleware | Purpose |
|---|---|
| **Recovery** | Catches panics, logs with `slog`, returns 500. Never leaks panic message to client. |
| **RequestID** | Reads `X-Request-ID` or generates UUID. Echoes in response header. |
| **Logging** | Structured per-request log: method, path, status, duration, request_id, remote_addr. |
| **Metrics** | Prometheus `http_requests_total` (counter, by method/path/status) and `http_request_duration_seconds` (histogram). |
| **Auth** | Parses JWT, builds `Principal`, attaches to context. Per-request blocked/revoked check. |
| **RateLimit** | Per-IP token bucket on `/auth/*` endpoints. 5 req/s, burst 10. Trusts `X-Forwarded-For` only when `TRUST_PROXY=1`. |

---

## 9. Cryptography

`internal/crypto/aesgcm.go`. AES-256-GCM, stdlib only.

```go
func (s *AESGCMService) Encrypt(plain []byte) (cipherText, nonce []byte, err error)
func (s *AESGCMService) Decrypt(cipherText, nonce []byte) (plain []byte, err error)
```

Properties:
- Key length checked at construction — exactly 32 bytes, or constructor returns an error.
- Nonce is generated fresh per encryption via `crypto/rand`. Never reused.
- GCM provides authentication (AEAD) — ciphertext tampering is detected during decryption.
- Decryption returns a generic "decryption failed" error — no oracle for key validation vs. data corruption.

`AES_KEY_HEX` is validated at server startup: exactly 64 hex characters. Server exits if invalid.

---

## 10. Audit log events

Every state-changing operation emits an audit event. Audit reads are paginated and filterable by event type and date range. Events are append-only at the application level — no API exists to delete them.

| Event | Trigger |
|---|---|
| `user_registered` | Successful registration |
| `user_logged_in` | Successful login |
| `user_blocked` / `user_unblocked` | Admin action on a user |
| `project_created` | New project |
| `project_member_added` / `_removed` / `_role_changed` | Membership changes |
| `project_team_assigned` / `_unassigned` | Team↔project linkage |
| `secret_created` / `_revoked` / `_rotated` / `_rolled_back` | Secret lifecycle |
| `secret_read` | Successful value read |
| `secret_read_denied` | Failed value read |
| `access_granted` / `access_revoked` | Grant lifecycle |
| `service_account_created` / `_revoked` | SA lifecycle |

Each event carries `actor_user_id`, optional `project_id` and `secret_id`, plus a `metadata JSONB` blob for context-specific fields.

---

## 11. Permissions matrix

| Action | `developer` | `manager` | `admin` | Global `is_admin` |
|---|---|---|---|---|
| Read secret metadata | ✓ | ✓ | ✓ | — |
| Read secret value | grant only | ✓ | ✓ | — |
| Create / rotate / rollback secret | ✗ | ✓ | ✓ | — |
| Revoke secret | ✗ | ✓ | ✓ | — |
| Grant / revoke access | ✗ | ✓ | ✓ | — |
| List grants | ✗ | ✓ | ✓ | — |
| Manage project members | ✗ | ✗ | ✓ | — |
| Assign / unassign teams | ✗ | ✗ | ✓ | — |
| List all users | ✗ | ✗ | ✗ | ✓ |
| Block / unblock users | ✗ | ✗ | ✗ | ✓ |
| Global audit log | ✗ | ✗ | ✗ | ✓ |
| Platform statistics | ✗ | ✗ | ✗ | ✓ |

`developer` can read a secret value only if a non-expired `access_grant` exists for them.

---

## 12. Production deployment notes

What you'd need to harden this for a real production deployment. None of these are bugs — they're scope choices documented honestly.

**Bring your own KMS.** Don't pass `AES_KEY_HEX` directly in production env vars. Load it from AWS KMS / GCP KMS / Vault Transit at startup. Losing the key means losing every encrypted secret — back it up, separately from the database.

**TLS termination upstream.** The service speaks plain HTTP. Put it behind nginx, Caddy, or a cloud load balancer. If you do, set `TRUST_PROXY=1` so the rate limiter reads the real client IP from `X-Forwarded-For`.

**Database-level audit hardening.** The audit log is append-only at the application layer — no API endpoint to delete events. At the PostgreSQL level, a superuser can still tamper. For regulated environments, add trigger-based append-only enforcement or ship audit events to an external append-only store (Loki, BigQuery, S3 + Object Lock).

**Cache the per-request blocked/revoked check.** The auth middleware looks up the actor's current status in the database on every request. At low traffic this is fine. Above ~100 RPS, cache the status with a 10-second TTL — accepts a 10-second window for revocation to take effect in exchange for one DB round-trip per request.

**Rotate the AES key.** The service stores all versions encrypted under the same key. To rotate, you'd need a re-encryption job: decrypt with the old key, encrypt with the new, swap. Not implemented yet.

**Automate secret rotation.** Versioning is supported; rotation policy is not. Pair with an external scheduler that calls `/secrets/{id}/rotate` on a schedule, optionally invoking a customer-provided rotation hook to update downstream systems.

**Run integration tests in CI with Docker available.** The repository's `integration/` tests use testcontainers-go and require a Docker daemon. They cover the full HTTP → service → DB path including the access-grant chain and per-request revocation. The CI workflow in `.github/workflows/ci.yml` is configured to run them.

---

*Last updated: 2026. For changes since publication, see git history and [SECURITY.md](./SECURITY.md).*

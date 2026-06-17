# Security

This file documents the pre-publication security audit of Secret Service, the vulnerabilities found, and how they were fixed before the repository was made public.

> **Why publish this?** Quietly patching findings and hoping no one notices the diff is the wrong move for a project whose entire purpose is handling secrets. If you're considering using this code, you deserve to see what was wrong, what was fixed, and how I think about defense-in-depth. If you're considering hiring me, this is the level of self-review I apply to my own work before showing it to anyone.

---

## Pre-publication audit (June 2026)

Before the first public commit, I did a focused security review of the codebase. I found 13 issues and fixed all of them in the same pass. They're listed below by severity.

### Critical

#### 1. IDOR in access grants
**Files:** `internal/access/service.go`, `internal/access/contracts.go`

`Grant`, `Revoke`, and `List` accepted both a `projectID` (from the URL path) and a `secretID` (from the request body or path) but never verified that the secret actually belonged to that project. A `manager` of project A could grant or revoke access to a secret in project B, given just its UUID.

**Fix:** added `ensureSecretInProject` — a single helper called at the top of every grant operation. Returns `ErrNotFound` (not `ErrForbidden` — don't leak existence) if the secret isn't in the URL's project.

#### 2. Service-account tokens accepted on user-only endpoints
**Files:** `internal/domain/principal.go`, `internal/middleware/auth.go`, `internal/secret/service.go`

The auth middleware parsed the JWT and extracted a `userID` regardless of whether the token's `sub` was `user` or `service_account`. Handlers that should have been user-only (block/unblock user, list all users, global audit) didn't re-check the subject, so an SA token could call them.

**Fix:** introduced `domain.Principal` with a `Kind` field. `Principal.GetUserID()` returns the empty string for non-user principals, so any handler that requires a user is automatically protected. Service accounts now have a separate code path that resolves project scope and explicitly cannot reach user-only endpoints.

#### 3. Rate limiter bypass via spoofed `X-Forwarded-For`
**Files:** `internal/middleware/ratelimit.go`, `internal/http/router.go`

The rate limiter keyed buckets on `X-Forwarded-For` when present. Without a reverse proxy in front, this means an attacker could spoof the header on each request and never hit the limit on `/auth/login`.

**Fix:** added `TRUST_PROXY` environment variable. `X-Forwarded-For` is honored only when explicitly enabled. Default behavior uses the actual peer address.

#### 4. JWTs without `exp`, `iss`, or `aud` validation
**Files:** `internal/token/jwt.go`

Tokens were validated only for signature. A token issued without an `exp` claim would never expire. A token signed with the same secret but a different issuer would still be accepted.

**Fix:** parser now requires `WithExpirationRequired()`, validates issuer and audience via `WithIssuer`/`WithAudience`, and pins the algorithm with `WithValidMethods([]string{"HS256"})` to defeat algorithm-confusion attacks (e.g., `alg: none`).

### High

#### 5. JWT not invalidated when a user is blocked or an SA is revoked
**Files:** `internal/authz/validator.go`, `internal/middleware/auth.go`

A blocked user could keep using their JWT until it expired (up to 24h). Same for a revoked service account (1h, but still a window).

**Fix:** per-request DB lookup of the actor's current status. Blocked users and revoked SAs are rejected immediately, regardless of token validity. The cost is one query per authenticated request — see [DOCUMENTATION.md](./DOCUMENTATION.md#12-production-deployment-notes) for the caching recommendation at scale.

#### 6. User enumeration via login timing
**Files:** `internal/auth/service.go`

If the email didn't exist, `Login` returned `ErrUserNotFound` after a fast lookup. If the email existed but the password was wrong, `Login` ran bcrypt comparison first. The timing difference let an attacker enumerate valid emails.

**Fix:** single error response `ErrInvalidCreds` for both cases. When the user doesn't exist, `bcrypt.CompareHashAndPassword` is still called against a dummy hash to equalize timing. The `is_blocked` check moved to after password verification — knowing that an account is blocked also leaks its existence.

#### 7. Password validation
**Files:** `internal/auth/password.go`

bcrypt silently truncates input to 72 bytes. A user could register with a 200-character password thinking it strong; only the first 72 bytes would matter.

**Fix:** explicit `ValidatePassword` — minimum 8, maximum 72 bytes. Empty passwords rejected. No silent truncation.

### Medium

#### 8. Unbounded pagination and lookahead
**Files:** `internal/dto/pagination.go`, `internal/handler/secret.go`

`offset` had no upper bound — a client could request offset=1e9 and force a slow scan. `ListExpiringSecrets` accepted any `days` value and would happily query "expiring in the next 100,000 days."

**Fix:** caps. `maxOffset = 100000`, `maxExpiringDays = 3650`. Requests above the cap return `400 Bad Request`.

#### 9. `ListExpiringSecrets` silently hid already-expired secrets
**Files:** `internal/storage/secret_repo.go`

The query was `WHERE expires_at > NOW() AND expires_at <= NOW() + days`. If a secret had already expired, it was filtered out — which is the exact opposite of what an admin querying "what's expiring" wants to see.

**Fix:** dropped the `expires_at > NOW()` filter. Already-expired secrets now appear at the top of the result.

#### 10. `AssignTeam` accepted arbitrary role strings
**Files:** `internal/handler/project.go`

`POST /api/v1/projects/{id}/teams` accepted a `role` field but didn't validate it against the allowed set (`admin`, `manager`, `developer`). A misspelled role like `"managar"` would be silently stored, breaking subsequent role checks.

**Fix:** explicit validation against allowed roles. Returns `400 Bad Request` for unknown values.

#### 11. `ListByProject` for service accounts didn't check role
**Files:** `internal/serviceaccount/service.go`

Any project member could list all service accounts in the project. Service-account metadata isn't catastrophic to leak, but listing them is the first step in mapping a project's CI/CD topology.

**Fix:** restricted to admin/manager.

### Low

#### 12. `respondErr` nil panic
**Files:** `internal/handler/helpers.go`

Passing `nil` as the error to `respondErr` panicked. A panicked handler returns a 500 with no audit event. Combined with fragile substring matching on bcrypt error messages, this was a small but real robustness issue.

**Fix:** nil-safe. Service layer now returns explicit sentinel errors that the handler maps cleanly; no more substring matching on third-party error messages.

#### 13. Swallowed audit errors
**Files:** `internal/audit/service.go`

If the audit write failed, the calling operation continued silently. For a service whose audit log is part of its value proposition, this is the wrong default.

**Fix:** centralized error path in `audit.Service.Log`. Failures are logged via `slog.ErrorContext` with the event type and reason. The calling operation still continues (failing the operation because audit failed would create its own DoS vector), but the failure is now visible and alertable.

---

## Verification

After applying the 13 fixes:

- `go build ./...` — clean
- `go vet ./...` — clean
- `gofmt` — clean
- Unit tests — all pass
- Added 5 new unit-test suites covering #2 (SA token rejected on user route), #4 (token without `exp` / wrong issuer / wrong audience rejected), #7 (password length boundaries), #8 (pagination cap), and #11 (X-Forwarded-For respected only with `TRUST_PROXY=1`)
- Integration tests compile and pass review by inspection; they require Docker (testcontainers-go) and are wired into CI

## Where the codebase stands now

After the audit, I don't see a critical vulnerability remaining. To be specific about what I checked:

- **Cryptography:** AES-256-GCM with a fresh random nonce per encryption, authenticated. Key length validated at startup. No homegrown crypto.
- **SQL:** every query parameterized; no string concatenation of user input.
- **Sensitive data in responses:** `password_hash` and `token_hash` excluded from JSON via struct tags; verified in tests.
- **Panic safety:** recovery middleware in front of every handler; no panic messages reach the client.
- **Configuration hygiene:** `JWT_SECRET ≥ 32 chars` and `AES_KEY_HEX = 32 bytes` validated at startup; server exits otherwise.

What I'd still want to do before declaring this "production-ready" for a serious deployment:

1. Run the integration test suite under CI with a real Docker daemon (currently set up but unverified — pending the first CI build to complete green).
2. Add a fuzz test for the JWT parser using `go test -fuzz`.
3. Threat-model the multi-project model end-to-end with someone other than me. Audits by their own author have a known blind-spot problem.

## Reporting future issues

If you find a security issue in this code, please open a [GitHub Security Advisory](https://github.com/AlexLe024/secret-service/security/advisories/new) rather than a public issue. I'll respond within seven days.

# Case Study: Secret Service

**A self-hosted secrets manager for development teams, written in Go.**

> Why this case study exists: a README explains *what the project is*. A case study explains *what I did and why* — the decisions, trade-offs, and what I learned. This is what I'd want a hiring manager or client to read before talking to me.

---

## The problem

Small engineering teams keep secrets in the wrong places.

I've seen it on three different teams during my internships: `.env` files in private repos that someone forgets to add to `.gitignore`. Database passwords pinned in Slack DMs. API keys living in a shared Notion page that nobody remembers to rotate when an engineer leaves.

The proper answer is a secrets manager — HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager. But for a 5–10 person team, running Vault is overkill, and cloud secret managers create vendor lock-in and a per-secret cost that grows faster than the team realizes.

I wanted to know: **what's the smallest set of features a team actually needs, and how cleanly can I build it in Go?**

This became my graduation project at Ural Federal University.

---

## What I built

A single Go binary that runs against PostgreSQL and provides:

- Encrypted secret storage (AES-256-GCM)
- Versioning with rollback to any previous version
- Project-scoped role-based access control (admin / manager / developer)
- Time-bound access grants (give someone read access for 24 hours, auto-expires)
- Service accounts for CI/CD (short-lived JWTs, scoped to one project)
- Environments (dev / staging / prod) and arbitrary tags
- Append-only audit log
- Prometheus metrics + Swagger UI
- A CLI client (`ss`) that fits into shell scripts

**By the numbers:** ~7,300 lines of Go, 9 SQL migrations, integration tests against a real Postgres via testcontainers, multi-stage Docker build, ~1,500-line documentation.

---

## Decisions and trade-offs

A case study without trade-offs is just marketing. Here's what I actually wrestled with.

### 1. PostgreSQL with sqlx, not an ORM

I considered GORM. I rejected it because:
- ORMs hide what queries you're running. For a service whose audit story has to be solid, this is unacceptable.
- sqlx gives me named parameters and struct scanning without giving up SQL control.

**Trade-off:** more boilerplate in repository code. **Why I'd do it again:** I've seen exactly one query in this project go wrong, and I found it in under a minute because the query was visible in the code.

### 2. Layered architecture (domain → service → repository → handler)

I deliberately avoided "clean architecture" purity. No separate use-case package, no DTO mapping ceremony for every layer. Just:
- `domain/` for pure Go structs
- `service/` for business logic + permission checks
- `storage/` for repository implementations
- `handler/` for HTTP

**Trade-off:** in a much larger codebase I'd separate use-cases from services. **Why I'd do it again:** at 7k lines, the extra layer is overhead with no benefit.

### 3. JWT with two subjects — `user` and `service_account`

Most tutorials show JWTs for users. Few show how to extend that for machine-to-machine auth without inventing a second auth system.

I added a `sub` field to the JWT claims: `user` (24h TTL) vs `service_account` (1h TTL, scoped to a project). The same middleware handles both — it just checks `sub` and routes the request accordingly.

**Trade-off:** in production I'd probably move service accounts to opaque tokens (random strings, looked up server-side) so I can revoke instantly without waiting for TTL to expire. JWTs are stateless and revocation is hard. **Why JWT for v1:** it kept the operational surface area smaller for a graduation project.

### 4. AES-256-GCM with a single key from environment

I considered:
- Per-tenant keys (rejected — too much key management for v1)
- KMS integration (rejected — extra infra dependency for a graduation project)
- Plain AES-CBC (rejected — no authenticated encryption, easy to misuse)

GCM gives me authenticated encryption with a clean stdlib API. The nonce is generated per-encryption and stored alongside the ciphertext.

**Trade-off:** if the env var leaks, every secret leaks. **Production answer:** load the key from KMS at startup, never persist it. I documented this in the README as a production requirement, not a feature gap to hide.

### 5. Append-only audit at the application level, not enforced at DB level

I emit audit events from the service layer. There's no API endpoint to delete them, and they're written in the same transaction as the operation they describe — so an audit event for "secret read" can't disappear without the read itself being undone.

**Trade-off:** at the database level a Postgres superuser can still tamper. For regulated environments (HIPAA, SOC 2) you'd need trigger-based append-only enforcement or an external append-only store like Loki or BigQuery. **Why I left it at the application level:** the project's target audience is small teams without a compliance officer, where the threat model is "leaked secret in Slack," not "rogue DBA covering tracks."

### 6. Integration tests with real PostgreSQL via testcontainers

I refused to mock the database. Mocks of database behavior are notoriously wrong — they don't catch SQL syntax errors, they don't catch constraint violations, they don't catch transaction issues.

Each integration test spins up a real Postgres container, runs migrations, and exercises the HTTP → service → DB path. Slower than unit tests, but every test that passes proves something real.

---

## What was actually hard

**Permission checks.** Encryption is well-understood — AES-GCM has one correct usage. Permissions are open-ended. "Can user A read secret S?" depends on project membership, role, active access grants, expiration times, secret status, and whether the actor is a user or a service account. I rewrote the access-check function three times before it was both correct and readable.

**JWT for two subject types in one middleware.** The first version branched in the middleware itself. The second version branched in every handler. The third version (which shipped) parses the JWT once in the middleware, puts a small `Principal` struct into the request context, and lets each handler read just the fields it cares about. Much cleaner.

**Graceful shutdown with in-flight requests.** I learned the hard way that `http.Server.Shutdown` doesn't cancel in-flight requests — it stops accepting new ones and waits. So a slow request can extend shutdown past the timeout. I added a context to the server with a 10-second deadline, which propagates through handler chains.

**Resisting feature creep.** Multiple times I wanted to add features I'd seen in Vault — dynamic secrets, SSH certificate signing, PKI. Each time I asked: *will a team of five with no Vault budget actually use this?* The answer was usually no. The scope is small on purpose.

---

## What I'd do differently next time

- **Opaque tokens for service accounts.** As above. JWT was the wrong choice for machine credentials.
- **A built-in rate limiter that respects multiple buckets.** The current rate limiter is per-IP. For service accounts, per-account would be more accurate.
- **Background secret-rotation policies.** The service supports versioning, but rotation is manual. A scheduler that rotates secrets older than N days, calling out to user-provided rotation hooks, would close the loop.
- **Better CLI UX.** The cobra commands work, but the prompts are minimal. A real product would have interactive flows for first-time setup.

---

## Skills demonstrated

If you're hiring and you want to know what working with me looks like, this project shows:

| Skill | Where it's in the code |
|---|---|
| **Go fundamentals + idiomatic style** | Layered architecture, interfaces over concrete types, no unnecessary dependencies |
| **Database design** | 9 migrations, foreign keys with cascades, check constraints, partial indexes (`WHERE is_current = TRUE`) |
| **API design** | RESTful resource hierarchy, consistent error responses, OpenAPI documentation |
| **Authentication & authorization** | JWT with multi-subject claims, RBAC, time-bound grants |
| **Cryptography** | AES-256-GCM with nonce handling, bcrypt for passwords, key length validation at startup |
| **Testing** | Integration tests against real Postgres (testcontainers), unit tests for crypto and JWT |
| **Operations** | Multi-stage Docker build, non-root container user, graceful shutdown, structured logging, Prometheus metrics |
| **Documentation** | 1,500-line technical doc, Swagger UI, this case study |
| **Honest engineering judgement** | Documented trade-offs and known limitations in the README rather than hiding them |

---

## What's next for the project

I'll keep it on GitHub as a portfolio piece. I'm not aiming to build a product out of it — Vault and Doppler exist. But I'd be happy to extend it for a client who wants something self-hosted and small.

If you're reading this because you're considering hiring me — this is the level of care I bring to backend work. I'd love to bring it to your project.

---

**Tech:** Go 1.25, PostgreSQL 14, chi, sqlx, JWT, AES-256-GCM, Prometheus, Docker, testcontainers-go
**Source:** [github.com/your-username/secret-service](https://github.com/your-username/secret-service)
**Live demo:** [demo.your-domain.com](https://demo.your-domain.com) — credentials in the README
**Contact:** [your.email@example.com] · [linkedin.com/in/yourhandle]

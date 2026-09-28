# Interview guide: Containerized CLI Login

This guide explains the implementation, the security properties it aims to provide, and the tradeoffs behind its design. It is written to help you explain the project in an interview. Be precise about the limits: this is a small single-service learning project, not a complete production identity platform.

## 1. What the program does

The project is an interactive Go CLI that lets a user register an account, authenticate with a password, optionally add TOTP-based two-factor authentication, and use commands within a server-side session. PostgreSQL stores durable state. Docker Compose runs PostgreSQL and provides an interactive container for the CLI. The CLI is intentionally launched with `docker compose run`, because it needs an attached terminal.

The key security goals are:

- Never store a user password in plaintext.
- Never issue an authenticated session after only the password step when MFA is enabled.
- Store only a digest of a session token in PostgreSQL.
- Encrypt TOTP secrets at rest and store only digests of recovery codes.
- Enforce lockout and session expiry in the database-backed service, not only in the prompt.

## 2. Architecture and request flow

```text
cmd/cli-login
  ├─ config.Load() ── validates environment configuration
  ├─ store.Store ──── pgx connection pool to PostgreSQL
  ├─ migrations.Apply() ── creates/updates schema
  ├─ auth.Service ─── authentication, MFA, lockout, and sessions
  └─ cli.Shell ────── readline prompt, commands, and presentation
```

The `internal` packages are deliberately not public Go libraries. The command entry point wires dependencies together. The CLI gathers input and renders output; the auth service owns security decisions; the store owns SQL and persistence; models hold domain records; security holds cryptographic helpers; config parses and validates environment variables; migrations embed versioned SQL.

### Registration

1. Trim and validate the username against a narrow ASCII rule set.
2. Check password length and a small common-password denylist. Passwords over bcrypt's 72-byte input limit are rejected.
3. Hash the password with bcrypt at the configured cost.
4. Insert the account. The database's unique constraint remains the final authority for duplicate usernames, including concurrent registrations.
5. Record an audit event. Audit failures are logged and do not change whether registration succeeds.

### Login without MFA

1. Look up the account. For an unknown username, perform a dummy bcrypt comparison to reduce the timing difference between known and unknown accounts.
2. Reject an account that is currently locked.
3. Verify the supplied password against the bcrypt hash.
4. Record failures and apply lockout at the configured threshold.
5. On success, clear failed attempts, update last-login time, generate a random token, store its SHA-256 digest in the session row, and return the raw token to the CLI.

### Login with MFA

The password stage returns a short-lived `PendingLogin`, not a session. The user then supplies a six-digit TOTP or a recovery code. The service reloads the account and rechecks lockout before verifying the second factor. Only a valid second factor completes session creation. This separation prevents password-only access from receiving an authenticated session.

TOTP uses the standard 30-second time step and six-digit SHA-1 profile supported by common authenticator apps. A configurable skew accepts nearby steps to handle small clock drift. Once a valid step is matched, the database records the timestep and rejects reuse of that code for a second login.

### MFA enrollment and recovery

Enabling MFA starts with an in-memory enrollment containing a random secret, provisioning URI, and eight recovery codes. The secret is not persisted until the user proves enrollment by entering a valid code. The app prints a QR code and manual secret. On confirmation, the secret is encrypted and the recovery codes are hashed before storing. Recovery codes are shown once, are single-use, and are consumed atomically. Disabling MFA requires the account password; security-sensitive MFA changes revoke the user's other sessions.

## 3. Security decisions

### Passwords: bcrypt

Bcrypt is an adaptive password hashing function, so an offline attacker has to spend substantial work per guess. Its cost is configurable and validated. The implementation rejects inputs above 72 bytes because bcrypt truncates longer inputs; silently truncating would make distinct long passwords equivalent. Password policy emphasizes minimum length and rejects common values, username-containing values, and a single repeated character. It does not enforce uppercase/digit/symbol composition rules because those rules often encourage predictable substitutions.

The common-password block list is deliberately small. It is useful for a demonstration, but a deployed service should use a maintained breach-password source or another appropriate policy. Bcrypt cost should be benchmarked for the target hardware and login latency.

### Username enumeration

For unknown usernames, the service runs a comparison against a dummy bcrypt hash. This reduces a straightforward timing signal, though it cannot promise that every path has identical latency. Login errors are kept generic for invalid credentials.

### TOTP secret encryption: AES-256-GCM

The authenticator secret must be recoverable by the application to calculate codes, so password hashing is not suitable. AES-256-GCM provides authenticated encryption. Each encryption uses a fresh random nonce; the stored value is nonce followed by ciphertext and authentication tag. A user-specific additional authenticated data value binds the ciphertext to its account ID, so copying a ciphertext into another user's row fails authentication.

The encryption key is provided separately through `APP_ENCRYPTION_KEY`, not stored in the database. This limits the value of a database-only read leak. The key must be backed up securely and kept stable: if it is lost, existing MFA secrets cannot be decrypted. Production operations would normally use a secret manager or KMS and plan key rotation.

### Sessions: random bearer token, digest in database

The CLI receives a cryptographically random 256-bit token. PostgreSQL stores its SHA-256 digest, not the token itself. If the session table is read, the attacker does not immediately obtain usable bearer tokens. A fast hash is appropriate because tokens are random and high entropy; bcrypt is reserved for human-chosen passwords.

Each session has an idle expiry and an absolute expiry. Successful authenticated commands slide the idle deadline forward, but a database update caps it at the absolute deadline and refuses revoked/expired sessions. Logout revokes the row server-side. The raw token is cached locally when session persistence is enabled so restarting the CLI can resume the session. That local token is sensitive: protect the state directory and disable persistence on shared machines.

### Lockout and concurrency

Failed password, TOTP, and recovery-code attempts contribute to a configurable counter. The database update owns the counter and lockout timestamp, so restarting the CLI does not reset the state. The service checks a lock before password verification and checks again before the MFA step. Database operations are used for state transitions that need atomicity, such as consuming recovery codes and marking a TOTP timestep as used.

Account lockout can also be abused to deny service to a victim. A public internet service may prefer rate limits by account and source, progressive delays, alerting, and recovery controls instead of relying only on a hard lock. This CLI has no remote client-IP boundary or web request middleware.

### SQL and schema safety

Queries use pgx parameters rather than string interpolation for user-controlled values. The schema defines unique constraints, foreign keys, checks, and indexes to preserve invariants and support lookups. Migrations are embedded in the binary and applied on startup. A PostgreSQL advisory lock serializes concurrent migration attempts.

### Logs and audit events

Structured application logs go to stderr, leaving stdout for the interactive transcript. The database audit history supports a `history` command. Audit writes are best effort so an audit table outage does not lock everyone out. This means the audit trail is useful operational history, not a tamper-proof compliance record; a production system would export it to protected centralized storage and define retention/access policy.

## 4. Database model

The initial migration defines these core tables:

| Table | Purpose | Sensitive material |
| --- | --- | --- |
| `users` | Identity, password hash, lockout and MFA metadata | bcrypt hash, encrypted TOTP secret |
| `sessions` | Server-side session expiry and revocation | SHA-256 token digest, never raw token |
| `mfa_recovery_codes` | Single-use recovery credentials | SHA-256 code digests, never raw codes |
| `auth_events` | Authentication and account security history | Usernames and event details; no passwords or OTP values |

The schema source is `internal/migrations/sql/0001_init.sql`. The migration runner embeds SQL from that directory, tracks applied versions, and uses a transaction/advisory lock to avoid concurrent schema changes.

## 5. Docker and persistence

Compose defines a PostgreSQL service with a health check and a named `db-data` volume. The CLI waits for PostgreSQL health and connects over the private Compose network. The database port is not published to the host by default. A separate named volume stores local CLI state (session token cache and prompt history) across replacement of CLI containers.

The Dockerfile is multi-stage: the builder uses the Go toolchain and produces a stripped static Linux binary; the runtime image contains only Alpine runtime support, timezone data, CA certificates, and the binary. The process runs as a non-root user. The entrypoint is the CLI binary. The `cli` Compose service uses a profile and TTY/stdin settings because it is an interactive application.

Use `docker compose down` to stop services while keeping named volumes. `docker compose down -v` removes both volumes and permanently deletes the account/session database and the persisted CLI state.

## 6. CLI design

`internal/cli` implements a readline shell with persistent history, password masking, tab completion, help, state-aware command visibility, and typo suggestions. Commands are held in one registry that defines each command's usage, help text, auth visibility, and handler. The same registry drives dispatch, help, and completion, reducing the chance those interfaces drift apart.

The shell supports cancellation of the current prompt with Ctrl-C and exits on Ctrl-D. After login it automatically shows username, registration time, MFA status, prior login, and current session deadlines. `whoami` repeats that summary. The command `history` refers to authentication audit activity; readline's command history is separate.

## 7. Configuration

The source of defaults and validation is `internal/config/config.go`; `.env.example` documents the operator-facing values. Important settings include:

| Variable | Default | What it controls |
| --- | --- | --- |
| `DATABASE_URL` | required | PostgreSQL connection |
| `APP_ENCRYPTION_KEY` | required | AES-256 key for stored TOTP secrets |
| `BCRYPT_COST` | `12` | Password hashing work factor |
| `MAX_FAILED_ATTEMPTS` | `5` | Failures before account lockout |
| `LOCKOUT_DURATION` | `15m` | Lockout duration |
| `SESSION_IDLE_TIMEOUT` | `15m` | Sliding inactivity deadline |
| `SESSION_ABSOLUTE_TIMEOUT` | `12h` | Maximum session lifetime |
| `SESSION_PERSIST` | `true` | Cache token locally between CLI runs |
| `TOTP_SKEW` | `1` | Adjacent 30-second steps accepted |
| `MIN_PASSWORD_LENGTH` | `10` | Registration password length floor |

Configuration is validated once at startup, including cross-field constraints such as idle timeout not exceeding absolute timeout. `genkey` works before configuration loading, since it generates the value that configuration requires.

## 8. Tests and how to discuss them

Unit tests exist alongside config, models, security, migrations, CLI, auth, and store packages. Store tests that need PostgreSQL can be enabled with `TEST_DATABASE_URL`; Compose includes a test service for that mode. This implementation pass generated the missing `go.sum` and confirmed that `go build ./cmd/cli-login` succeeds locally. Tests were not run during this pass.

Good areas to explain in a code walkthrough:

1. Why MFA login is split into a pending state and a completed session.
2. Why session tokens are hashed but TOTP secrets are encrypted.
3. How the database protects against replay and duplicate recovery-code use.
4. Why session expiry is checked in SQL when sliding the idle deadline.
5. How the CLI is kept separate from authentication policy.

## 9. Limitations and next steps

This project is intentionally compact. Before using it for real accounts, address these limits:

- There is no distributed rate limiter or source/network throttling. Account lockout is per user and may enable denial of service.
- `APP_ENCRYPTION_KEY` is environment configuration, not a managed KMS integration; key rotation and recovery need an operational plan.
- Persistent local sessions store a bearer token in the CLI state directory. File permissions and endpoint security matter.
- The common-password denylist is small and is not a breach-password service.
- Audit events are best effort and live in the same database as the application data.
- There is no administrator workflow, password reset, account deletion, or MFA reset process.
- Compose disables PostgreSQL TLS because the database is reachable only on its private local network. Remote deployments must configure TLS and use verified certificates.
- The app is a CLI exercise, not an HTTP service. It has no web transport, CSRF, browser session, or internet-facing authorization layer.

Reasonable follow-up work would include integration testing against PostgreSQL in CI, stronger operational secret management, a recovery/admin process, configurable audit retention, and monitoring/alerting.

## 10. Interview questions to practice

**Why bcrypt instead of SHA-256 for passwords?**

SHA-256 is designed to be fast. If a password database leaks, attackers can test guesses rapidly. Bcrypt is deliberately expensive and has a tunable work factor, which raises the cost of each guess.

**Why is the session token hashed with SHA-256 rather than bcrypt?**

The session token is generated randomly with 256 bits of entropy, unlike a human password. It is infeasible to guess, so a fast digest is sufficient and allows efficient lookup by digest.

**Why encrypt TOTP secrets but hash recovery codes?**

The application needs the original TOTP secret to verify codes, so it must be decryptable. Recovery codes are only compared with user input, so storing a digest is enough and avoids recoverable secrets in the database.

**What does the AES-GCM additional authenticated data do?**

It binds the encrypted secret to a user identifier without encrypting that identifier. If someone copies ciphertext between account rows, authentication fails because the associated data is different.

**Why does MFA setup wait for a confirmation code before saving the secret?**

It proves the user has enrolled the displayed secret before changing the account's authentication requirements. A failed setup does not leave the account in a partially enabled state.

**What are the session timeout semantics?**

An authenticated command extends an idle deadline, but the deadline is capped by an absolute expiration. Both deadlines and revocation are enforced in PostgreSQL, so application restarts do not reset them.

**What happens if PostgreSQL is unavailable?**

The CLI cannot authenticate or validate a session, because the source of truth is the database. It reports a startup/operation error rather than treating cached local state as authorization.

**What would you change before production?**

I would add source-based rate limiting and monitoring, use a KMS or secret manager for the encryption key, protect and potentially disable local token persistence on shared hosts, set up backup/restore and key rotation procedures, and export audit events to controlled storage. I would also run integration tests against the supported PostgreSQL version in CI.

## 11. Useful source map

| Area | Files |
| --- | --- |
| Process startup and dependency wiring | `cmd/cli-login/main.go` |
| Authentication, MFA, lockout, and sessions | `internal/auth/auth.go` |
| Shell and commands | `internal/cli/` |
| Configuration | `internal/config/config.go` |
| PostgreSQL persistence | `internal/store/` |
| Cryptography and password helpers | `internal/security/` |
| Schema and migration runner | `internal/migrations/` |
| Container setup | `Dockerfile`, `docker-compose.yml` |

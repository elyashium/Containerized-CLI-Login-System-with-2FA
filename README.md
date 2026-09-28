# Containerized CLI Login System with Optional 2FA

A secure interactive command-line login system: user registration, password
authentication, optional TOTP two-factor authentication (Google Authenticator
compatible), account lockout, and server-side session management — running in
Docker with PostgreSQL for persistence.

Written in Go 1.23. No state lives in the application: accounts and sessions are
stored in the database, so data survives container restarts and replacement.

```
  ┌─────────────────────────┐        ┌──────────────────────────┐
  │  cli-login container    │        │  postgres:16 container   │
  │                         │        │                          │
  │  readline shell         │◀──────▶│  users                   │
  │  auth service           │  pgx   │  sessions                │
  │  bcrypt · AES-GCM · TOTP│        │  mfa_recovery_codes      │
  │                         │        │  auth_events             │
  └───────────┬─────────────┘        └────────────┬─────────────┘
              │ volume: cli-state                 │ volume: db-data
      session token cache + history          durable account data
```

---

## Contents

- [Quick start](#quick-start)
- [Commands](#commands)
- [Walkthrough](#walkthrough)
- [Configuration](#configuration)
- [Security design](#security-design)
- [Database schema](#database-schema)
- [Data persistence](#data-persistence)
- [Tests](#tests)
- [Local development without Docker](#local-development-without-docker)
- [Design decisions](#design-decisions)
- [Project layout](#project-layout)
- [Troubleshooting](#troubleshooting)

---

## Quick start

**Requirements:** Docker with Compose v2 (`docker compose`, not `docker-compose`).
Nothing else — no local Go toolchain needed.

### With `make`

```bash
make setup    # creates .env, generates an encryption key, builds the image
make up       # starts PostgreSQL and waits for it to report healthy
make cli      # opens the interactive login shell
```

`make help` lists every target.

### Without `make`

```bash
cp .env.example .env
```

Generate the encryption key that protects TOTP secrets at rest and paste it
into `.env` as `APP_ENCRYPTION_KEY`:

```bash
docker compose run --rm --no-deps cli genkey
```

Then start the database and open the shell:

```bash
docker compose up -d db
docker compose run --rm cli
```

The CLI applies its own migrations on startup, so the schema is created on first
run. There is no separate setup step.

> **Why is the CLI not started by `docker compose up`?**
> It is an interactive TTY program. `docker compose up` would leave it running
> with nobody attached to its terminal. It sits behind a compose profile so
> `up` starts only the database, and `docker compose run --rm cli` attaches your
> terminal properly.

### Shutting down

```bash
docker compose down     # stop containers, keep all data
docker compose down -v  # stop containers and delete all accounts (make clean)
```

---

## Commands

The command set changes with your authentication state, and `help` only ever
lists what you can actually run right now.

**Before logging in**

| Command | Description |
| --- | --- |
| `register` | Create a new account |
| `login` | Sign in with username and password (plus 2FA if enabled) |
| `help` | Show available commands; `help <command>` for details |
| `exit` | Quit (alias: `quit`) |

**After logging in**

| Command | Description |
| --- | --- |
| `whoami` | Show account and session details |
| `enable-2fa` | Turn on TOTP two-factor authentication |
| `disable-2fa` | Turn off 2FA (requires your password) |
| `history` | Show recent account activity — `history [count]` |
| `logout` | End the session server-side |
| `help` | Show available commands |
| `exit` | Quit, leaving the session active |

`register` and `login` are hidden while signed in; the rest are hidden while
signed out. Asking for one anyway gets an explanation rather than
"unknown command".

**Shell features**

- **Tab completion** for command names, and for the argument to `help`.
  Suggestions are filtered by your current state.
- **Command history** with ↑/↓, persisted to `$STATE_DIR/history` across runs.
- **Typo suggestions**: typing `regsiter` answers with a "Did you mean" hint
  pointing at `register` (anything within edit distance 2 of a command you can
  currently run).
- **Ctrl-C** cancels the prompt you are in without ending the session;
  **Ctrl-D** exits.
- Colour is disabled automatically when output is not a terminal, or when
  `NO_COLOR` or `TERM=dumb` is set.

**Non-interactive subcommands**

```bash
docker compose run --rm --no-deps cli genkey    # print a fresh encryption key
docker compose run --rm cli version             # print the version
docker compose run --rm --build migrate         # apply migrations and exit
```

---

## Walkthrough

The blocks below show the interface as the code renders it.

### Register

```
auth> register

Create an account
  Username: 3-32 characters, letters/digits/._- only, must start with a letter or digit
  Password: at least 10 characters
  Username: alice
  Password: ************
  Confirm password: ************

✔ Account alice created.
  Run `login` to sign in.
```

### Log in

The account and session summary is printed automatically after every successful
login, and on demand with `whoami`.

```
auth> login

Sign in
  Username: alice
  Password: ************

✔ Signed in as alice.

Account
  Username               alice
  Registered             2026-09-28 14:02:11 UTC (6 minutes ago)
  Two-factor auth        disabled
  Last login             first login

Session
  Started                2026-09-28 14:08:40 UTC (just now)
  Expires                2026-09-28 14:23:40 UTC (in 15 minutes)
  Idle timeout           15 minutes
  Hard expiry            2026-09-29 02:08:40 UTC (in 12 hours)

alice@auth>
```

"Last login" is the login *before* this one — showing the current one would only
ever say "now". "Expires" is the effective deadline: the earlier of the sliding
idle timeout and the hard cap.

### Enable 2FA

```
alice@auth> enable-2fa

Enable two-factor authentication
  Scan this QR code with Google Authenticator, 1Password, Authy or
  any other TOTP app:

    ▄▄▄▄▄▄▄ ▄  ▄▄ ▄ ▄▄▄▄▄▄▄
    █ ▄▄▄ █ ▀▄▀█▄▀▀ █ ▄▄▄ █
    █ ███ █ █ ▄ ▀▄█ █ ███ █
    ▀▀▀▀▀▀▀ ▀ ▀ ▀ ▀ ▀▀▀▀▀▀▀
             (etc.)

  Can't scan? Enter this key manually:
  Secret key             JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP
  Account                alice (CLI Login)

  Enter the 6-digit code shown in your app: 492517

✔ Two-factor authentication is now enabled.

Recovery codes
  Store these somewhere safe. Each one can be used once, in place of
  your authenticator code, if you lose access to your device.

    K7M2Q-XR94T
    B3HDN-PW82K
    ... (8 in total)

! They will not be shown again.
```

Enrolment is confirmed before it takes effect: the secret is only stored after
you enter a valid code from your app, so a mis-scanned QR code cannot lock you
out. Enabling 2FA also signs out your other sessions, since those were opened
under the weaker single-factor policy.

### Log in with 2FA

```
auth> login

Sign in
  Username: alice
  Password: ************

› Two-factor authentication is enabled for alice.
  Enter the 6-digit code from your authenticator app, or a recovery code.
  Authentication code: 492517

✔ Signed in as alice.
```

A correct password alone never produces a session when 2FA is on — see
[Two-stage login](#two-stage-login).

### Account lockout

```
auth> login

Sign in
  Username: alice
  Password: ******

✘ Invalid username or password.
  After 5 failed attempts the account is locked for 15 minutes.
```

…and once the threshold is reached:

```
✘ Account locked after 5 failed attempts.
  Try again in 15 minutes.
```

### Activity log

```
alice@auth> history

Recent activity (latest 5)
  2026-09-28 14:31:02  ok    login_success    session opened
  2026-09-28 14:31:01  ok    login_totp       totp accepted
  2026-09-28 14:30:58  ok    login_password   password accepted
  2026-09-28 14:29:14  fail  login_password   bad password
  2026-09-28 14:02:11  ok    register         account created
```

---

## Configuration

Everything is read from the environment. `docker compose` loads `.env`
automatically; `.env.example` documents each variable inline.

**Required**

| Variable | Description |
| --- | --- |
| `DATABASE_URL` | PostgreSQL connection string. Set by `docker-compose.yml` from the `POSTGRES_*` values below. |
| `APP_ENCRYPTION_KEY` | 32-byte AES-256 key protecting TOTP secrets at rest. Accepts base64 (standard, raw, or URL-safe) or hex. Generate with `make genkey`. |

**Database**

| Variable | Default | Description |
| --- | --- | --- |
| `POSTGRES_DB` | `clilogin` | Database name |
| `POSTGRES_USER` | `app` | Database user |
| `POSTGRES_PASSWORD` | `change_me_in_dotenv` | Database password — change it |
| `DB_CONNECT_TIMEOUT` | `30s` | How long to retry the initial connection at startup |

**Password storage**

| Variable | Default | Description |
| --- | --- | --- |
| `BCRYPT_COST` | `12` | bcrypt work factor, 10–31. Each +1 doubles hashing time. |
| `MIN_PASSWORD_LENGTH` | `10` | Minimum password length, at least 8 |

**Account lockout**

| Variable | Default | Description |
| --- | --- | --- |
| `MAX_FAILED_ATTEMPTS` | `5` | Consecutive failures (wrong password *or* wrong 2FA code) before locking |
| `LOCKOUT_DURATION` | `15m` | How long the account stays locked |

**Sessions**

| Variable | Default | Description |
| --- | --- | --- |
| `SESSION_IDLE_TIMEOUT` | `15m` | Sliding inactivity window; every authenticated command pushes it forward |
| `SESSION_ABSOLUTE_TIMEOUT` | `12h` | Hard lifetime cap regardless of activity. Must be ≥ the idle timeout. |
| `SESSION_PERSIST` | `true` | Cache the session token on disk so a session survives restarting the CLI |
| `STATE_DIR` | `/home/app/.cli-login` | Where the token cache and command history live |

**Two-factor authentication**

| Variable | Default | Description |
| --- | --- | --- |
| `TOTP_ISSUER` | `CLI Login` | Label shown beside the account in the authenticator app |
| `TOTP_SKEW` | `1` | 30-second steps accepted either side of now, for clock drift (0–10) |
| `PENDING_LOGIN_TTL` | `2m` | How long a half-finished login (password accepted, 2FA outstanding) stays valid |

**Misc**

| Variable | Default | Description |
| --- | --- | --- |
| `LOG_LEVEL` | `warn` | `debug`, `info`, `warn` or `error`. Logs go to stderr, keeping stdout clean. |
| `TZ` | `UTC` | Timezone for rendering timestamps |

Invalid configuration is rejected at startup, and **every** problem is reported
at once rather than one per run:

```
error: invalid configuration:
  - BCRYPT_COST must be between 10 and 31, got 4
  - SESSION_IDLE_TIMEOUT (1h0m0s) must not exceed SESSION_ABSOLUTE_TIMEOUT (30m0s)
```

---

## Security design

### Password storage

Passwords are hashed with **bcrypt** at cost 12 — never stored or logged in
plaintext. bcrypt silently truncates input beyond 72 bytes, which would make two
different long passwords interchangeable, so inputs over 72 bytes are rejected
explicitly rather than quietly accepted.

The only password policy is a length minimum (10 by default) plus a check
against reuse of the username. Character-class rules ("one digit, one symbol")
push users toward predictable substitutions without adding real entropy, so they
are deliberately absent.

### Account lockout

After `MAX_FAILED_ATTEMPTS` consecutive failures the account locks for
`LOCKOUT_DURATION`. A wrong 2FA code counts as a failure, so the second factor
is rate-limited too.

The increment and the threshold check happen in **a single SQL statement**:

```sql
UPDATE users
SET failed_attempts = failed_attempts + 1,
    locked_until = CASE WHEN failed_attempts + 1 >= $2
                        THEN now() + $3::interval ELSE locked_until END
WHERE id = $1
RETURNING ...
```

A read-modify-write in application code would let two simultaneous failed logins
both read `4`, both write `5`, and lose a failure. `internal/store` has a
concurrency test asserting that eight parallel failures record as eight.

### Username enumeration

A login attempt against a username that does not exist performs a bcrypt
comparison against a dummy hash before failing. Without it, "no such user"
returns in microseconds while "wrong password" takes ~250ms, and that timing
difference alone reveals which accounts exist. The error message is identical
either way: `Invalid username or password.`

### Session management

- Tokens are 256 bits from `crypto/rand`, URL-safe base64 encoded.
- Only the **SHA-256 digest** is stored. A dump of the `sessions` table yields
  nothing usable. (A fast digest is right here: unlike a password, a 256-bit
  random token is not guessable, so key stretching buys nothing.)
- Two expiries: a **sliding idle timeout** refreshed by every authenticated
  command, and a **hard absolute cap** that activity cannot extend. The
  `UPDATE` that slides the idle deadline clamps it with
  `LEAST(now() + interval, absolute_expires_at)`.
- Validity is re-checked **inside** that `UPDATE`, not before it, so a
  late-arriving command cannot revive a session that has already lapsed.
- `logout` revokes the session in the database. Changing 2FA settings revokes
  every *other* session for the account.

With `SESSION_PERSIST=true` the token is cached in `$STATE_DIR/session.json`
(mode `0600`, in a `0700` directory) so restarting the CLI resumes the session
until it genuinely expires. Every start revalidates against the database — a
cached token for a revoked or expired session is discarded.

### Two-stage login

When 2FA is enabled, a correct password produces a short-lived `PendingLogin`
handle, not a session. Only a valid TOTP or recovery code converts it into one.
The distinction matters: a design that issues the session first and then "asks
for" the code leaves a usable session behind for anyone who ignores the prompt.

The handle expires after `PENDING_LOGIN_TTL` (2 minutes), so an abandoned
half-finished login does not stay resumable.

### TOTP

- SHA-1, 6 digits, 30-second period — the RFC 6238 profile Google Authenticator
  and every other mainstream app implement.
- Secrets are 160-bit (RFC 4226's recommendation for HMAC-SHA1).
- Secrets are **encrypted at rest with AES-256-GCM** under
  `APP_ENCRYPTION_KEY`, with the user ID bound in as additional authenticated
  data — so a secret copied from one row to another fails to decrypt. A database
  dump alone cannot generate valid codes.
- Codes are verified in constant time by the `pquerna/otp` library.
- **Replay is blocked.** A code stays valid for its whole window (≈90 seconds
  with skew 1), so `mfa_last_timestep` records the last accepted step and a
  login is only accepted if its step is strictly greater:

  ```sql
  UPDATE users SET mfa_last_timestep = $2
  WHERE id = $1 AND (mfa_last_timestep IS NULL OR mfa_last_timestep < $2)
  ```

  The guard being in the `WHERE` clause means two concurrent logins with the
  same code cannot both succeed. There is a test for exactly that.

### Recovery codes

Eight single-use codes are issued at enrolment, formatted `XXXXX-XXXXX` from a
31-symbol alphabet that omits look-alike characters (`0`/`O`, `1`/`I`/`L`) —
~49 bits of entropy each. Only SHA-256 digests are stored. Claiming a code uses
`SELECT ... FOR UPDATE` inside a transaction, so a code cannot be spent twice.
Disabling 2FA destroys the secret and all remaining codes.

Random selection uses rejection sampling rather than `rand.Read() % n`, which
would bias the first few symbols of the alphabet.

### Audit trail

`auth_events` records registrations, password and 2FA outcomes, lockouts,
logouts and session expiries — visible to the user via `history`. Failed logins
against a *non-existent* username are recorded too (with a null `user_id`),
which is exactly when you most want the record. Audit writes never block
authentication: a failure there is logged and the login proceeds.

### Container hardening

The runtime image is `alpine:3.20` with a statically linked binary
(`CGO_ENABLED=0`), no Go toolchain, and a non-root user (uid 10001). The
database publishes **no host port** — it is reachable only on the private
compose network — and initialises with `scram-sha-256` rather than `md5`.

### Known limitations

Worth stating plainly, since a threat model with no boundaries is not a threat
model:

- `sslmode=disable` is used between the containers. The connection never leaves
  the private compose network, but any real deployment should point
  `DATABASE_URL` at a TLS-enabled server with `sslmode=verify-full`.
- `APP_ENCRYPTION_KEY` lives in `.env`, not a secrets manager. It is the right
  shape for one (a single opaque value read from the environment), but this is
  not KMS.
- Lockout is per-account, not per-IP, and there is no global rate limit. In a
  single-host CLI tool there is no client identity to key one on.
- Losing `APP_ENCRYPTION_KEY` makes enrolled TOTP secrets undecryptable.
  Affected users must re-enrol; there is no key-rotation path.

---

## Database schema

Migrations live in [`internal/migrations/sql/`](internal/migrations/sql/) and are
embedded in the binary with `go:embed`, so the image carries its own schema and
there is no separate migration artifact to keep in sync.

They run automatically on every startup. Each is applied once, recorded in
`schema_migrations`, and the whole run is wrapped in a **PostgreSQL advisory
lock** — so starting several containers simultaneously is safe. Each migration
runs in its own transaction and rolls back cleanly on failure.

| Table | Purpose |
| --- | --- |
| `users` | Accounts: credentials, lockout state, 2FA enrolment |
| `sessions` | Live and revoked sessions, keyed by token digest |
| `mfa_recovery_codes` | Single-use backup codes (digests only) |
| `auth_events` | Append-only audit trail |
| `schema_migrations` | Which migrations have been applied |

```
users
  id                BIGSERIAL PK
  username          TEXT NOT NULL          -- as typed, for display
  username_lower    TEXT NOT NULL UNIQUE   -- lookup key: case-insensitive identity
  password_hash     TEXT NOT NULL          -- bcrypt
  created_at        TIMESTAMPTZ NOT NULL   -- "Registration date" in the details block
  updated_at        TIMESTAMPTZ NOT NULL
  last_login_at     TIMESTAMPTZ            -- NULL until the first login
  failed_attempts   INT NOT NULL DEFAULT 0
  locked_until      TIMESTAMPTZ            -- NULL when not locked
  mfa_enabled       BOOLEAN NOT NULL DEFAULT FALSE
  mfa_secret        BYTEA                  -- AES-256-GCM sealed
  mfa_enrolled_at   TIMESTAMPTZ
  mfa_last_timestep BIGINT                 -- TOTP replay guard

sessions
  id                  BIGSERIAL PK
  user_id             BIGINT NOT NULL → users(id) ON DELETE CASCADE
  token_hash          BYTEA NOT NULL UNIQUE  -- SHA-256; the token itself is never stored
  created_at          TIMESTAMPTZ NOT NULL
  last_seen_at        TIMESTAMPTZ NOT NULL
  idle_expires_at     TIMESTAMPTZ NOT NULL   -- slides forward on activity
  absolute_expires_at TIMESTAMPTZ NOT NULL   -- never moves
  revoked_at          TIMESTAMPTZ            -- set by logout
  client_info         TEXT

mfa_recovery_codes
  id         BIGSERIAL PK
  user_id    BIGINT NOT NULL → users(id) ON DELETE CASCADE
  code_hash  BYTEA NOT NULL     -- SHA-256 of the normalized code
  created_at TIMESTAMPTZ NOT NULL
  used_at    TIMESTAMPTZ        -- NULL while unspent

auth_events
  id         BIGSERIAL PK
  user_id    BIGINT → users(id) ON DELETE SET NULL  -- nullable: unknown-username attempts
  username   TEXT                                   -- denormalized, survives deletion
  event_type TEXT NOT NULL
  success    BOOLEAN NOT NULL
  detail     TEXT
  created_at TIMESTAMPTZ NOT NULL
```

Inspect it directly with:

```bash
make psql
```

Sessions and recovery codes cascade on user deletion; audit rows are kept with a
null `user_id`, because deleting an account should not erase the record that it
existed.

---

## Data persistence

Account data lives in the `db-data` named volume, not in the container's
writable layer. To demonstrate that it survives:

```bash
docker compose run --rm cli      # register an account, then exit
docker compose restart db        # or: docker compose down && docker compose up -d db
docker compose run --rm cli      # log in — the account is still there
```

`make restart-db` runs the restart step and shows the container's health.

Two volumes are in play:

| Volume | Contents | Effect |
| --- | --- | --- |
| `db-data` | PostgreSQL data directory | Accounts and sessions survive restarts and container replacement |
| `cli-state` | Session token cache, shell history | A *session* survives restarting the CLI, until it times out server-side |

`docker compose down` keeps both. `docker compose down -v` (`make clean`)
deletes both — that is the only way to lose the accounts.

---

## Tests

The unit tests are **hermetic** — no database, no network, no filesystem
fixtures. They run inside the image build, so a broken build cannot produce an
image:

```dockerfile
RUN go test ./...
```

Run them yourself with a local Go toolchain:

```bash
make test         # go test ./... -count=1
make test-cover   # with a coverage summary
```

Covered: password hashing and the 72-byte boundary; AES-GCM sealing, including
tampering and cross-user AAD rejection; token, recovery-code and TOTP-secret
generation; recovery-code normalization; username and password validation;
configuration parsing, defaults and aggregated error reporting; every encryption
key encoding; command-registry integrity and the two command sets the brief
specifies; tab completion; typo suggestion and edit distance; duration and
timestamp formatting; the migration loader's ordering and version checks.

### Integration tests

`internal/store` additionally tests the SQL itself — atomic lockout counting,
single-use recovery codes, the replay guard, the idle/absolute expiry clamp.
Those need a real PostgreSQL, so they **skip themselves** unless
`TEST_DATABASE_URL` is set. That is a runtime skip rather than a build tag
precisely so `go test ./...` stays hermetic in the image build.

To run everything, including them:

```bash
make test-integration
```

That starts the database and runs the suite in a container on the compose
network (`docker compose run --rm --build tests`), so no host port is published
and no local Go toolchain is needed.

---

## Local development without Docker

You need Go 1.23+ and a PostgreSQL you can reach.

`go.sum` is not committed. Generate it first:

```bash
make deps        # go mod tidy
```

Then:

```bash
make check       # gofmt -s -w . && go vet ./... && go test ./...
make build-local # → bin/cli-login
```

To point the binary at a database, publish the compose port by uncommenting the
`ports:` block in `docker-compose.yml`, then:

```bash
export DATABASE_URL="postgres://app:change_me_in_dotenv@localhost:5432/clilogin?sslmode=disable"
export APP_ENCRYPTION_KEY="$(go run ./cmd/cli-login genkey)"
go run ./cmd/cli-login
```

---

## Design decisions

### PostgreSQL rather than SQLite

The brief recommends SQLite for simplicity but also requires that the database
"run in a container" and persist across restarts. SQLite is a library, not a
server: containerizing it means containerizing the application and putting the
file on a volume, which makes "the database runs in a container" true only in a
strained sense.

PostgreSQL makes the requirement literal — a separate `db` service, a named
volume, a healthcheck the CLI waits on — and the security-critical operations
here are precisely the ones that benefit from real concurrency semantics.
Lockout counting, recovery-code claiming and TOTP replay prevention are all
implemented as single atomic statements; under SQLite's single-writer model the
same code would work but the property would be incidental rather than
demonstrated. The cost is one extra container, which Compose makes free.

### Sessions in the database, not in a file

A token cached on disk could be checked locally, which would be simpler and
wrong: `logout` could not end a session from elsewhere, and a stolen file would
be a permanent credential. Sessions live in the database and are revalidated on
every authenticated command. The local cache holds only the token, and is
useless once the row is revoked.

### Compose profiles for the CLI

An interactive TTY program does not belong in `docker compose up`. Putting the
`cli` service behind a profile means `up` starts only the database, while
`docker compose run --rm cli` (which enables the profile itself) attaches your
terminal correctly. The same mechanism keeps the one-shot `migrate` and `tests`
services out of normal startup.

### Migrations embedded and run on startup

`go:embed` keeps the schema inside the binary, so the image cannot drift from
the migrations it needs. Running them on every startup — idempotent, advisory-
locked, one transaction each — means the CLI is usable immediately after
`docker compose up` with no separate setup step to forget. `cli-login migrate`
exists for CI, where you may want the schema without a shell.

### All SQL in one package

`internal/store` owns every query; higher layers work with domain types and
never build SQL. For a project whose correctness claims are mostly about what
the SQL guarantees, having one auditable query surface is worth more than the
convenience of scattering queries where they are used.

### A registry-driven shell

Commands are values in a table with their own metadata and visibility rules
(`requiresAuth` / `requiresGuest`), so `help`, tab completion, dispatch and typo
suggestion all derive from one source. Adding a command cannot leave `help`
stale or completion out of step. A test pins the brief's two command sets, so
changing what is available in either state fails the build rather than drifting
quietly.

### Errors the user can act on

Every failure says what happened and what to do next — `!` for warnings, `✘`
for errors, a dimmed hint underneath. Security messages stay deliberately vague
about *which* credential was wrong while being specific about consequences
("After 5 failed attempts the account is locked for 15 minutes"). Internal
error-wrapping prefixes are stripped before display, so the user sees
"Must be at least 10 characters", not
"password does not meet requirements: must be at least 10 characters".

---

## Project layout

```
cli-login/
├── cmd/cli-login/main.go        entrypoint, subcommands, wiring
├── internal/
│   ├── auth/                    authentication service: the security policy
│   │   auth.go                  register, login, 2FA enrolment, sessions
│   ├── cli/                     interactive shell
│   │   shell.go                 REPL, session restore, user-details block
│   │   commands.go              command registry and implementations
│   │   prompt.go                readline wrapper: history, masked input
│   │   output.go                colour, alignment, time formatting
│   │   state.go                 session token cache on disk
│   ├── config/config.go         environment parsing and validation
│   ├── migrations/              embedded SQL, advisory-locked runner
│   │   sql/0001_init.sql        the schema
│   ├── models/models.go         domain types, no SQL or crypto
│   ├── security/                cryptographic primitives
│   │   security.go              bcrypt, tokens, recovery codes, TOTP secrets
│   │   crypto.go                AES-256-GCM sealing of TOTP secrets
│   └── store/                   all SQL
│       store.go                 users, lockout, 2FA, recovery codes
│       sessions.go              sessions and the audit trail
├── Dockerfile                   multi-stage; tests run in the build
├── docker-compose.yml           db + cli + migrate + tests
├── .env.example                 every setting, documented inline
└── Makefile                     convenience targets
```

Dependencies are deliberately few: `pgx` (PostgreSQL driver),
`golang.org/x/crypto` (bcrypt), `pquerna/otp` (TOTP), `chzyer/readline`
(line editing), `mdp/qrterminal` (terminal QR codes). Everything else —
sessions, lockout, validation, output formatting — is standard library.

---

## Troubleshooting

**`APP_ENCRYPTION_KEY is required`**

The key is unset or empty in `.env`. Generate one and paste it in:

```bash
docker compose run --rm --no-deps cli genkey
```

Or let `make setup` do it. The error message names the variable and the
`genkey` command.

**`connect to database: database unreachable after 30s`**

The database is not running or not healthy yet:

```bash
docker compose ps db
docker compose logs db
```

`docker compose up -d db` waits for the healthcheck. If the volume was
initialised with a different `POSTGRES_PASSWORD`, the credentials in `.env` no
longer match it — either restore the old password or `make clean` to start over
(which deletes all accounts).

**The QR code is unreadable or looks like garbage**

It needs a terminal with a Unicode font and enough width. Widen the window, or
use the `Secret key` printed underneath and enter it manually in your app.

**`the input device is not a TTY` (Git Bash / MSYS on Windows)**

`docker compose run` needs a real terminal. Use PowerShell or Windows Terminal,
or prefix with `winpty`:

```bash
winpty docker compose run --rm cli
```

**Arrow keys print `^[[A` instead of recalling history**

The CLI is not attached to a TTY. Use `docker compose run --rm cli`, not
`docker compose exec` against a container started without `tty: true`.

**`invalid or expired 2FA code` with a code straight from the app**

Almost always clock drift. TOTP depends on both sides agreeing on the time.
Check the host clock, and raise `TOTP_SKEW` (each step is 30 seconds) if the
device is persistently off. If you cannot get in, use a recovery code — the
login prompt accepts either.

**Locked out and unwilling to wait**

Wait out `LOCKOUT_DURATION`, or clear it directly:

```bash
make psql
```
```sql
UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE username_lower = 'alice';
```

**Tests fail during `docker compose build`**

That is deliberate — `RUN go test ./...` blocks a broken image. Run
`make test` locally to see the failures with full output.

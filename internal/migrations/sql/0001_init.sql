-- 0001_init.sql — initial schema for the CLI login system.
--
-- Design notes:
--   * All timestamps are TIMESTAMPTZ so behaviour is correct regardless of the
--     container's local timezone.
--   * Secrets are never stored in a directly usable form: passwords are bcrypt
--     hashes, session tokens are stored as SHA-256 digests, TOTP secrets are
--     AES-256-GCM ciphertext, and recovery codes are SHA-256 digests.
--   * username_lower gives case-insensitive uniqueness without depending on the
--     CITEXT extension being available in the image.

CREATE TABLE IF NOT EXISTS users (
    id                BIGSERIAL PRIMARY KEY,
    username          TEXT        NOT NULL,
    username_lower    TEXT        NOT NULL UNIQUE,
    password_hash     TEXT        NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Populated with the *previous* successful login so the CLI can show
    -- "last login" as something other than "just now".
    last_login_at     TIMESTAMPTZ,

    -- Lockout state. failed_attempts counts consecutive failures across both
    -- the password and the TOTP stage; it resets on any fully successful login.
    failed_attempts   INTEGER     NOT NULL DEFAULT 0,
    locked_until      TIMESTAMPTZ,

    -- TOTP / MFA state.
    mfa_enabled       BOOLEAN     NOT NULL DEFAULT FALSE,
    mfa_secret        BYTEA,      -- AES-256-GCM(nonce || ciphertext || tag)
    mfa_enrolled_at   TIMESTAMPTZ,
    mfa_last_timestep BIGINT      -- highest accepted TOTP step; blocks replay
);

-- Server-side sessions. The client only ever holds the raw token; the database
-- holds its digest, so a database leak cannot be replayed as a login.
CREATE TABLE IF NOT EXISTS sessions (
    id                  BIGSERIAL PRIMARY KEY,
    user_id             BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash          BYTEA       NOT NULL UNIQUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Sliding inactivity deadline, pushed forward on each authenticated action.
    idle_expires_at     TIMESTAMPTZ NOT NULL,
    -- Hard ceiling that sliding activity can never extend past.
    absolute_expires_at TIMESTAMPTZ NOT NULL,

    revoked_at          TIMESTAMPTZ,
    client_info         TEXT
);

CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions (user_id);
CREATE INDEX IF NOT EXISTS sessions_idle_expires_at_idx ON sessions (idle_expires_at);

-- Single-use recovery codes, issued when TOTP is enabled. Without these a user
-- who loses their authenticator device is permanently locked out.
CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  BYTEA       NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    used_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS mfa_recovery_codes_user_id_idx ON mfa_recovery_codes (user_id);

-- Append-only audit trail. username is denormalised so failed logins against
-- a non-existent account are still recorded.
CREATE TABLE IF NOT EXISTS auth_events (
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT      REFERENCES users(id) ON DELETE SET NULL,
    username   TEXT,
    event_type TEXT        NOT NULL,
    success    BOOLEAN     NOT NULL,
    detail     TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS auth_events_user_id_created_at_idx ON auth_events (user_id, created_at DESC);

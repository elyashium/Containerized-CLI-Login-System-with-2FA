// Package store owns all SQL. Higher layers work with domain types and never
// build queries themselves, which keeps the query surface auditable in one
// place and makes the auth service testable against a fake.
package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/shash/cli-login/internal/models"
)

// Sentinel errors returned to callers. Callers match on these with errors.Is
// rather than inspecting driver-specific error codes.
var (
	ErrNotFound         = errors.New("record not found")
	ErrUsernameTaken    = errors.New("username is already taken")
	ErrNoRecoveryCode   = errors.New("no matching unused recovery code")
	uniqueViolationCode = "23505"
)

// Store is a PostgreSQL-backed data store.
type Store struct {
	pool *pgxpool.Pool
}

// New connects to the database and verifies the connection is usable.
//
// The pool is created eagerly but pgx connects lazily, so we Ping in a retry
// loop: under docker-compose the app can start before Postgres finishes its
// first-boot initialisation even with a healthcheck in place.
func New(ctx context.Context, databaseURL string, connectTimeout time.Duration) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse DATABASE_URL: %w", err)
	}
	cfg.MaxConns = 8
	cfg.MaxConnLifetime = time.Hour
	cfg.MaxConnIdleTime = 15 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create connection pool: %w", err)
	}

	deadline := time.Now().Add(connectTimeout)
	var lastErr error
	for attempt := 1; ; attempt++ {
		pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		lastErr = pool.Ping(pingCtx)
		cancel()
		if lastErr == nil {
			return &Store{pool: pool}, nil
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			break
		}
		// Linear backoff capped at 2s keeps startup responsive without
		// hammering a database that is still initialising.
		wait := time.Duration(attempt) * 250 * time.Millisecond
		if wait > 2*time.Second {
			wait = 2 * time.Second
		}
		select {
		case <-ctx.Done():
			pool.Close()
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
	pool.Close()
	return nil, fmt.Errorf("database unreachable after %s: %w", connectTimeout, lastErr)
}

// Close releases all pooled connections.
func (s *Store) Close() { s.pool.Close() }

// Pool exposes the underlying pool for the migration runner.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Ping checks database liveness.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// userColumns is the shared SELECT list, so every scan target matches.
const userColumns = `
	id, username, password_hash, created_at, updated_at, last_login_at,
	failed_attempts, locked_until, mfa_enabled, mfa_secret, mfa_enrolled_at,
	mfa_last_timestep`

func scanUser(row pgx.Row) (*models.User, error) {
	var u models.User
	err := row.Scan(
		&u.ID, &u.Username, &u.PasswordHash, &u.CreatedAt, &u.UpdatedAt,
		&u.LastLoginAt, &u.FailedAttempts, &u.LockedUntil, &u.MFAEnabled,
		&u.MFASecret, &u.MFAEnrolledAt, &u.MFALastTimestep,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan user: %w", err)
	}
	return &u, nil
}

// CreateUser inserts a new account, returning ErrUsernameTaken if the
// (case-insensitive) username already exists.
func (s *Store) CreateUser(ctx context.Context, username, passwordHash string) (*models.User, error) {
	const q = `
		INSERT INTO users (username, username_lower, password_hash)
		VALUES ($1, $2, $3)
		RETURNING ` + userColumns

	row := s.pool.QueryRow(ctx, q, username, strings.ToLower(username), passwordHash)
	user, err := scanUser(row)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolationCode {
			return nil, ErrUsernameTaken
		}
		return nil, err
	}
	return user, nil
}

// GetUserByUsername looks up an account case-insensitively.
func (s *Store) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	const q = `SELECT ` + userColumns + ` FROM users WHERE username_lower = $1`
	return scanUser(s.pool.QueryRow(ctx, q, strings.ToLower(username)))
}

// GetUserByID looks up an account by primary key.
func (s *Store) GetUserByID(ctx context.Context, id int64) (*models.User, error) {
	const q = `SELECT ` + userColumns + ` FROM users WHERE id = $1`
	return scanUser(s.pool.QueryRow(ctx, q, id))
}

// RecordFailedAttempt increments the failure counter and locks the account once
// it reaches maxAttempts.
//
// The increment and the threshold check happen in a single statement so two
// concurrent failed logins cannot both read the same counter and each write
// back the same value, losing one failure.
func (s *Store) RecordFailedAttempt(ctx context.Context, userID int64, maxAttempts int, lockFor time.Duration) (*models.User, error) {
	const q = `
		UPDATE users
		SET failed_attempts = failed_attempts + 1,
		    locked_until = CASE
		        WHEN failed_attempts + 1 >= $2 THEN now() + $3::interval
		        ELSE locked_until
		    END,
		    updated_at = now()
		WHERE id = $1
		RETURNING ` + userColumns

	return scanUser(s.pool.QueryRow(ctx, q, userID, maxAttempts, lockFor.String()))
}

// ClearFailedAttempts resets lockout state after a fully successful login.
func (s *Store) ClearFailedAttempts(ctx context.Context, userID int64) error {
	const q = `
		UPDATE users
		SET failed_attempts = 0, locked_until = NULL, updated_at = now()
		WHERE id = $1`
	_, err := s.pool.Exec(ctx, q, userID)
	if err != nil {
		return fmt.Errorf("clear failed attempts: %w", err)
	}
	return nil
}

// TouchLastLogin advances last_login_at to loginAt, returning the value it
// held before the update. The CLI shows that previous value as "last login",
// which is what a user expects to see immediately after signing in.
func (s *Store) TouchLastLogin(ctx context.Context, userID int64, loginAt time.Time) (*time.Time, error) {
	// The CTE captures the old value before the UPDATE runs, so the returned
	// timestamp is unambiguously the previous login rather than the one we are
	// writing now.
	const q = `
		WITH previous AS (
			SELECT id, last_login_at FROM users WHERE id = $1
		)
		UPDATE users u
		SET last_login_at = $2, updated_at = now()
		FROM previous p
		WHERE u.id = p.id
		RETURNING p.last_login_at`

	var previous *time.Time
	err := s.pool.QueryRow(ctx, q, userID, loginAt).Scan(&previous)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("touch last login: %w", err)
	}
	return previous, nil
}

// SetMFASecret stores a sealed TOTP secret and flips MFA on, replacing any
// previously issued recovery codes with the supplied hashes.
//
// Everything runs in one transaction: a partial apply that enabled MFA without
// storing recovery codes would leave the user one lost phone away from being
// permanently locked out.
func (s *Store) SetMFASecret(ctx context.Context, userID int64, sealedSecret []byte, recoveryHashes [][]byte) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once committed

	const updateQ = `
		UPDATE users
		SET mfa_enabled = TRUE, mfa_secret = $2, mfa_enrolled_at = now(),
		    mfa_last_timestep = NULL, updated_at = now()
		WHERE id = $1`
	if _, err := tx.Exec(ctx, updateQ, userID, sealedSecret); err != nil {
		return fmt.Errorf("enable MFA: %w", err)
	}

	if _, err := tx.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("clear old recovery codes: %w", err)
	}
	for _, hash := range recoveryHashes {
		const insertQ = `INSERT INTO mfa_recovery_codes (user_id, code_hash) VALUES ($1, $2)`
		if _, err := tx.Exec(ctx, insertQ, userID, hash); err != nil {
			return fmt.Errorf("store recovery code: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit MFA enable: %w", err)
	}
	return nil
}

// DisableMFA turns MFA off and destroys the secret and all recovery codes.
func (s *Store) DisableMFA(ctx context.Context, userID int64) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const q = `
		UPDATE users
		SET mfa_enabled = FALSE, mfa_secret = NULL, mfa_enrolled_at = NULL,
		    mfa_last_timestep = NULL, updated_at = now()
		WHERE id = $1`
	if _, err := tx.Exec(ctx, q, userID); err != nil {
		return fmt.Errorf("disable MFA: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("delete recovery codes: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit MFA disable: %w", err)
	}
	return nil
}

// ConsumeTOTPTimestep records timestep as used, but only if it is strictly
// greater than the last accepted one.
//
// It reports false when the code has already been used. TOTP codes stay valid
// for a whole 30-second window (wider with skew), so without this an attacker
// who shoulder-surfs or replays a captured code can reuse it. The guard lives
// in the WHERE clause so concurrent logins cannot both succeed.
func (s *Store) ConsumeTOTPTimestep(ctx context.Context, userID int64, timestep int64) (bool, error) {
	const q = `
		UPDATE users SET mfa_last_timestep = $2, updated_at = now()
		WHERE id = $1 AND (mfa_last_timestep IS NULL OR mfa_last_timestep < $2)`
	tag, err := s.pool.Exec(ctx, q, userID, timestep)
	if err != nil {
		return false, fmt.Errorf("consume TOTP timestep: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// ConsumeRecoveryCode marks a single unused recovery code as spent, returning
// how many remain. It returns ErrNoRecoveryCode when the code is unknown or
// already used.
func (s *Store) ConsumeRecoveryCode(ctx context.Context, userID int64, codeHash []byte) (remaining int, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Claim exactly one matching unused code. LIMIT 1 via a subquery guards
	// against the (astronomically unlikely) case of duplicate hashes.
	const claimQ = `
		UPDATE mfa_recovery_codes SET used_at = now()
		WHERE id = (
			SELECT id FROM mfa_recovery_codes
			WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL
			ORDER BY id
			LIMIT 1
			FOR UPDATE
		)
		RETURNING id`
	var claimedID int64
	err = tx.QueryRow(ctx, claimQ, userID, codeHash).Scan(&claimedID)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNoRecoveryCode
	}
	if err != nil {
		return 0, fmt.Errorf("claim recovery code: %w", err)
	}

	const countQ = `SELECT count(*) FROM mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL`
	if err := tx.QueryRow(ctx, countQ, userID).Scan(&remaining); err != nil {
		return 0, fmt.Errorf("count remaining recovery codes: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit recovery code use: %w", err)
	}
	return remaining, nil
}

// CountUnusedRecoveryCodes reports how many recovery codes remain unspent.
func (s *Store) CountUnusedRecoveryCodes(ctx context.Context, userID int64) (int, error) {
	const q = `SELECT count(*) FROM mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL`
	var n int
	if err := s.pool.QueryRow(ctx, q, userID).Scan(&n); err != nil {
		return 0, fmt.Errorf("count recovery codes: %w", err)
	}
	return n, nil
}

// UpdatePasswordHash replaces a user's password hash.
func (s *Store) UpdatePasswordHash(ctx context.Context, userID int64, hash string) error {
	const q = `UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1`
	if _, err := s.pool.Exec(ctx, q, userID, hash); err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	return nil
}

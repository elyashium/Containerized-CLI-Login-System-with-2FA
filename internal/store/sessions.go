package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/elyashium/Containerized-CLI-Login-System-with-2FA/internal/models"
)

const sessionColumns = `
	id, user_id, created_at, last_seen_at, idle_expires_at,
	absolute_expires_at, revoked_at, coalesce(client_info, '')`

func scanSession(row pgx.Row) (*models.Session, error) {
	var s models.Session
	err := row.Scan(
		&s.ID, &s.UserID, &s.CreatedAt, &s.LastSeenAt, &s.IdleExpiresAt,
		&s.AbsoluteExpiresAt, &s.RevokedAt, &s.ClientInfo,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan session: %w", err)
	}
	return &s, nil
}

// CreateSession stores a new session keyed by the token's digest.
func (s *Store) CreateSession(
	ctx context.Context,
	userID int64,
	tokenHash []byte,
	idleTimeout, absoluteTimeout time.Duration,
	clientInfo string,
) (*models.Session, error) {
	const q = `
		INSERT INTO sessions (
			user_id, token_hash, idle_expires_at, absolute_expires_at, client_info
		)
		VALUES ($1, $2, now() + $3::interval, now() + $4::interval, $5)
		RETURNING ` + sessionColumns

	row := s.pool.QueryRow(ctx, q, userID, tokenHash,
		idleTimeout.String(), absoluteTimeout.String(), clientInfo)
	session, err := scanSession(row)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}
	return session, nil
}

// GetSessionByTokenHash fetches a session and its owner regardless of validity;
// the caller decides how to treat an expired or revoked row.
func (s *Store) GetSessionByTokenHash(ctx context.Context, tokenHash []byte) (*models.Session, *models.User, error) {
	const q = `
		SELECT ` + sessionColumns + `, ` + prefixedUserColumns + `
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = $1`

	var sess models.Session
	var u models.User
	err := s.pool.QueryRow(ctx, q, tokenHash).Scan(
		&sess.ID, &sess.UserID, &sess.CreatedAt, &sess.LastSeenAt,
		&sess.IdleExpiresAt, &sess.AbsoluteExpiresAt, &sess.RevokedAt, &sess.ClientInfo,
		&u.ID, &u.Username, &u.PasswordHash, &u.CreatedAt, &u.UpdatedAt,
		&u.LastLoginAt, &u.FailedAttempts, &u.LockedUntil, &u.MFAEnabled,
		&u.MFASecret, &u.MFAEnrolledAt, &u.MFALastTimestep,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("load session: %w", err)
	}
	return &sess, &u, nil
}

// prefixedUserColumns mirrors userColumns but qualified for the JOIN above.
const prefixedUserColumns = `
	u.id, u.username, u.password_hash, u.created_at, u.updated_at, u.last_login_at,
	u.failed_attempts, u.locked_until, u.mfa_enabled, u.mfa_secret, u.mfa_enrolled_at,
	u.mfa_last_timestep`

// TouchSession slides the idle deadline forward, but never past the absolute
// deadline and never for a session that is already revoked or expired.
//
// Doing the validity check inside the UPDATE means an expired session can
// never be revived by a late-arriving command.
func (s *Store) TouchSession(ctx context.Context, sessionID int64, idleTimeout time.Duration) (*models.Session, error) {
	const q = `
		UPDATE sessions
		SET last_seen_at = now(),
		    idle_expires_at = LEAST(now() + $2::interval, absolute_expires_at)
		WHERE id = $1
		  AND revoked_at IS NULL
		  AND idle_expires_at > now()
		  AND absolute_expires_at > now()
		RETURNING ` + sessionColumns

	session, err := scanSession(s.pool.QueryRow(ctx, q, sessionID, idleTimeout.String()))
	if err != nil {
		return nil, err // ErrNotFound here means "no longer valid"
	}
	return session, nil
}

// RevokeSession ends a single session. It is idempotent.
func (s *Store) RevokeSession(ctx context.Context, sessionID int64) error {
	const q = `UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`
	if _, err := s.pool.Exec(ctx, q, sessionID); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

// RevokeAllUserSessions ends every live session for a user. Called when MFA
// settings change, so a session opened under the old security posture cannot
// outlive it.
func (s *Store) RevokeAllUserSessions(ctx context.Context, userID int64, exceptSessionID int64) (int64, error) {
	const q = `
		UPDATE sessions SET revoked_at = now()
		WHERE user_id = $1 AND revoked_at IS NULL AND id <> $2`
	tag, err := s.pool.Exec(ctx, q, userID, exceptSessionID)
	if err != nil {
		return 0, fmt.Errorf("revoke user sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}

// DeleteExpiredSessions prunes rows that can no longer be used. Run at
// startup so the table does not grow without bound.
func (s *Store) DeleteExpiredSessions(ctx context.Context, olderThan time.Duration) (int64, error) {
	const q = `
		DELETE FROM sessions
		WHERE (absolute_expires_at < now() - $1::interval)
		   OR (revoked_at IS NOT NULL AND revoked_at < now() - $1::interval)`
	tag, err := s.pool.Exec(ctx, q, olderThan.String())
	if err != nil {
		return 0, fmt.Errorf("delete expired sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}

// RecordAuthEvent appends to the audit trail.
//
// Audit failures must never block authentication, so callers log and continue
// rather than failing the operation.
func (s *Store) RecordAuthEvent(ctx context.Context, userID *int64, username, eventType string, success bool, detail string) error {
	const q = `
		INSERT INTO auth_events (user_id, username, event_type, success, detail)
		VALUES ($1, $2, $3, $4, $5)`
	if _, err := s.pool.Exec(ctx, q, userID, username, eventType, success, detail); err != nil {
		return fmt.Errorf("record auth event: %w", err)
	}
	return nil
}

// RecentAuthEvents returns a user's most recent audit entries, newest first.
func (s *Store) RecentAuthEvents(ctx context.Context, userID int64, limit int) ([]models.AuthEvent, error) {
	const q = `
		SELECT id, user_id, coalesce(username, ''), event_type, success,
		       coalesce(detail, ''), created_at
		FROM auth_events
		WHERE user_id = $1
		ORDER BY created_at DESC, id DESC
		LIMIT $2`

	rows, err := s.pool.Query(ctx, q, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("query auth events: %w", err)
	}
	defer rows.Close()

	var events []models.AuthEvent
	for rows.Next() {
		var e models.AuthEvent
		if err := rows.Scan(&e.ID, &e.UserID, &e.Username, &e.EventType,
			&e.Success, &e.Detail, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan auth event: %w", err)
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate auth events: %w", err)
	}
	return events, nil
}

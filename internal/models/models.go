// Package models defines the domain types shared by the store, the auth
// service and the CLI.
package models

import "time"

// User is an account record. Secret material (password hash, encrypted TOTP
// secret) stays in this struct but is never rendered by the CLI.
type User struct {
	ID              int64
	Username        string
	PasswordHash    string
	CreatedAt       time.Time
	UpdatedAt       time.Time
	LastLoginAt     *time.Time
	FailedAttempts  int
	LockedUntil     *time.Time
	MFAEnabled      bool
	MFASecret       []byte // AES-256-GCM sealed; nil when MFA is off
	MFAEnrolledAt   *time.Time
	MFALastTimestep *int64
}

// IsLocked reports whether the account is currently locked out.
func (u *User) IsLocked(now time.Time) bool {
	return u.LockedUntil != nil && u.LockedUntil.After(now)
}

// LockRemaining returns how long the lockout still has to run, or zero.
func (u *User) LockRemaining(now time.Time) time.Duration {
	if !u.IsLocked(now) {
		return 0
	}
	return u.LockedUntil.Sub(now)
}

// Session is a server-side session record.
type Session struct {
	ID                int64
	UserID            int64
	CreatedAt         time.Time
	LastSeenAt        time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	RevokedAt         *time.Time
	ClientInfo        string
}

// ExpiresAt returns the moment the session will actually end: the earlier of
// the sliding idle deadline and the hard absolute deadline.
func (s *Session) ExpiresAt() time.Time {
	if s.AbsoluteExpiresAt.Before(s.IdleExpiresAt) {
		return s.AbsoluteExpiresAt
	}
	return s.IdleExpiresAt
}

// IsValid reports whether the session is neither revoked nor expired.
func (s *Session) IsValid(now time.Time) bool {
	return s.RevokedAt == nil && s.ExpiresAt().After(now)
}

// AuthEvent is one row of the audit trail.
type AuthEvent struct {
	ID        int64
	UserID    *int64
	Username  string
	EventType string
	Success   bool
	Detail    string
	CreatedAt time.Time
}

// Audit event type constants. Kept as typed constants so a typo in one call
// site cannot silently create a new event category.
const (
	EventRegister       = "register"
	EventLoginPassword  = "login_password"
	EventLoginTOTP      = "login_totp"
	EventLoginRecovery  = "login_recovery"
	EventLoginSuccess   = "login_success"
	EventLogout         = "logout"
	EventLockout        = "lockout"
	EventEnable2FA      = "enable_2fa"
	EventDisable2FA     = "disable_2fa"
	EventSessionExpired = "session_expired"
)

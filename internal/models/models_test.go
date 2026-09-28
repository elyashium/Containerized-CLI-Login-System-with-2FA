package models

import (
	"testing"
	"time"
)

var base = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func ptr(t time.Time) *time.Time { return &t }

func TestUserIsLocked(t *testing.T) {
	cases := []struct {
		name        string
		lockedUntil *time.Time
		want        bool
	}{
		{"never locked", nil, false},
		{"locked for another 5 minutes", ptr(base.Add(5 * time.Minute)), true},
		{"lock expired a minute ago", ptr(base.Add(-time.Minute)), false},
		{"lock expires exactly now", ptr(base), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := &User{LockedUntil: tc.lockedUntil}
			if got := u.IsLocked(base); got != tc.want {
				t.Errorf("IsLocked = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestUserLockRemaining(t *testing.T) {
	locked := &User{LockedUntil: ptr(base.Add(90 * time.Second))}
	if got := locked.LockRemaining(base); got != 90*time.Second {
		t.Errorf("LockRemaining = %s, want 1m30s", got)
	}

	// An expired or absent lock must report zero rather than a negative
	// duration, which would render as "-3m" in the CLI.
	expired := &User{LockedUntil: ptr(base.Add(-time.Hour))}
	if got := expired.LockRemaining(base); got != 0 {
		t.Errorf("LockRemaining on an expired lock = %s, want 0", got)
	}
	never := &User{}
	if got := never.LockRemaining(base); got != 0 {
		t.Errorf("LockRemaining with no lock = %s, want 0", got)
	}
}

func TestSessionExpiresAtTakesTheEarlierDeadline(t *testing.T) {
	cases := []struct {
		name     string
		idle     time.Time
		absolute time.Time
		want     time.Time
	}{
		{
			name:     "idle deadline comes first",
			idle:     base.Add(15 * time.Minute),
			absolute: base.Add(12 * time.Hour),
			want:     base.Add(15 * time.Minute),
		},
		{
			// Near the end of a long-lived session the hard cap wins, so
			// activity can no longer extend it.
			name:     "absolute cap comes first",
			idle:     base.Add(15 * time.Minute),
			absolute: base.Add(2 * time.Minute),
			want:     base.Add(2 * time.Minute),
		},
		{
			name:     "identical deadlines",
			idle:     base.Add(time.Hour),
			absolute: base.Add(time.Hour),
			want:     base.Add(time.Hour),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Session{IdleExpiresAt: tc.idle, AbsoluteExpiresAt: tc.absolute}
			if got := s.ExpiresAt(); !got.Equal(tc.want) {
				t.Errorf("ExpiresAt = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestSessionIsValid(t *testing.T) {
	live := func() *Session {
		return &Session{
			IdleExpiresAt:     base.Add(15 * time.Minute),
			AbsoluteExpiresAt: base.Add(12 * time.Hour),
		}
	}

	if !live().IsValid(base) {
		t.Error("a fresh session should be valid")
	}

	revoked := live()
	revoked.RevokedAt = ptr(base.Add(-time.Minute))
	if revoked.IsValid(base) {
		t.Error("a revoked session must never be valid, even before its deadlines")
	}

	idleExpired := live()
	idleExpired.IdleExpiresAt = base.Add(-time.Second)
	if idleExpired.IsValid(base) {
		t.Error("a session past its idle deadline must be invalid")
	}

	capReached := live()
	capReached.AbsoluteExpiresAt = base.Add(-time.Second)
	if capReached.IsValid(base) {
		t.Error("a session past its absolute deadline must be invalid")
	}

	exact := live()
	exact.IdleExpiresAt = base
	if exact.IsValid(base) {
		t.Error("a session expiring exactly now must be treated as expired")
	}
}

func TestEventTypeConstantsAreDistinct(t *testing.T) {
	// A copy-paste slip that gave two events the same string would silently
	// merge unrelated rows in the audit trail.
	events := []string{
		EventRegister, EventLoginPassword, EventLoginTOTP, EventLoginRecovery,
		EventLoginSuccess, EventLogout, EventLockout, EventEnable2FA,
		EventDisable2FA, EventSessionExpired,
	}
	seen := make(map[string]bool, len(events))
	for _, e := range events {
		if e == "" {
			t.Error("an event type constant is empty")
		}
		if seen[e] {
			t.Errorf("duplicate event type %q", e)
		}
		seen[e] = true
	}
}

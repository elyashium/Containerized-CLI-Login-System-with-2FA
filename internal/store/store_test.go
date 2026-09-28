package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shash/cli-login/internal/migrations"
	"github.com/shash/cli-login/internal/models"
)

// These tests need a real PostgreSQL instance, because the behaviour under test
// is the SQL itself: atomic lockout counting, single-use recovery codes and the
// replay guard are all enforced by the statements, not by Go code.
//
// The gate is a runtime skip rather than a build tag so `go test ./...` stays
// hermetic — that matters because the Docker image build runs it with no
// database available.
//
//	make test-integration        # brings up the db and sets TEST_DATABASE_URL
//	TEST_DATABASE_URL=... go test ./internal/store/

func newTestStore(t *testing.T) (*Store, context.Context) {
	t.Helper()

	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set TEST_DATABASE_URL to run store integration tests (see `make test-integration`)")
	}

	ctx := context.Background()
	st, err := New(ctx, url, 10*time.Second)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(st.Close)

	if _, err := migrations.Apply(ctx, st.Pool()); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	return st, ctx
}

var userCounter atomic.Int64

// newUser creates an account with a name unique to this run and removes it
// afterwards. Tests never truncate tables, so pointing TEST_DATABASE_URL at a
// database that holds other data is not destructive.
func newUser(t *testing.T, st *Store, ctx context.Context) *models.User {
	t.Helper()

	name := fmt.Sprintf("test_%d_%d", time.Now().UnixNano(), userCounter.Add(1))
	user, err := st.CreateUser(ctx, name, "$2a$04$notarealhashnotarealhashnotarealhashnotarealhash12")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	t.Cleanup(func() {
		cleanupCtx := context.Background()
		// auth_events only nulls its user_id on delete, so clear it explicitly.
		// Deleting the user cascades to sessions and recovery codes.
		_, _ = st.pool.Exec(cleanupCtx, `DELETE FROM auth_events WHERE user_id = $1`, user.ID)
		_, _ = st.pool.Exec(cleanupCtx, `DELETE FROM users WHERE id = $1`, user.ID)
	})
	return user
}

// tokenHash returns a digest-shaped value unique to this call. token_hash
// carries a UNIQUE constraint, so fixed literals would collide with rows left
// behind by an interrupted run.
func tokenHash(label string) []byte {
	return []byte(fmt.Sprintf("%s-%d-%d", label, time.Now().UnixNano(), userCounter.Add(1)))
}

// ------------------------------------------------------------------- users

func TestCreateUserAndLookup(t *testing.T) {
	st, ctx := newTestStore(t)
	user := newUser(t, st, ctx)

	if user.ID == 0 {
		t.Error("a created user should have an assigned id")
	}
	if user.MFAEnabled || user.FailedAttempts != 0 || user.LockedUntil != nil || user.LastLoginAt != nil {
		t.Error("a new account should start with MFA off, no failures and no prior login")
	}
	if user.CreatedAt.IsZero() {
		t.Error("created_at should be populated by the database default")
	}

	byName, err := st.GetUserByUsername(ctx, user.Username)
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if byName.ID != user.ID {
		t.Errorf("looked up id %d, want %d", byName.ID, user.ID)
	}

	// Case-insensitive lookup is what makes "Alice" and "alice" one account.
	byUpper, err := st.GetUserByUsername(ctx, strings.ToUpper(user.Username))
	if err != nil {
		t.Fatalf("GetUserByUsername with different case: %v", err)
	}
	if byUpper.ID != user.ID {
		t.Error("username lookup should be case-insensitive")
	}

	byID, err := st.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if byID.Username != user.Username {
		t.Errorf("GetUserByID returned %q, want %q", byID.Username, user.Username)
	}

	if _, err := st.GetUserByUsername(ctx, "definitely-not-registered-xyzzy"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown username should give ErrNotFound, got %v", err)
	}
}

func TestCreateUserRejectsDuplicatesRegardlessOfCase(t *testing.T) {
	st, ctx := newTestStore(t)
	user := newUser(t, st, ctx)

	if _, err := st.CreateUser(ctx, user.Username, "hash"); !errors.Is(err, ErrUsernameTaken) {
		t.Errorf("duplicate username should give ErrUsernameTaken, got %v", err)
	}
	if _, err := st.CreateUser(ctx, strings.ToUpper(user.Username), "hash"); !errors.Is(err, ErrUsernameTaken) {
		t.Errorf("duplicate username in another case should give ErrUsernameTaken, got %v", err)
	}
}

// ----------------------------------------------------------------- lockout

func TestRecordFailedAttemptLocksAtTheThreshold(t *testing.T) {
	st, ctx := newTestStore(t)
	user := newUser(t, st, ctx)

	const maxAttempts = 3
	const lockFor = 15 * time.Minute

	for i := 1; i < maxAttempts; i++ {
		updated, err := st.RecordFailedAttempt(ctx, user.ID, maxAttempts, lockFor)
		if err != nil {
			t.Fatalf("RecordFailedAttempt: %v", err)
		}
		if updated.FailedAttempts != i {
			t.Errorf("after %d failures the counter is %d", i, updated.FailedAttempts)
		}
		if updated.IsLocked(time.Now()) {
			t.Errorf("account locked after %d of %d attempts", i, maxAttempts)
		}
	}

	locked, err := st.RecordFailedAttempt(ctx, user.ID, maxAttempts, lockFor)
	if err != nil {
		t.Fatalf("RecordFailedAttempt: %v", err)
	}
	if locked.FailedAttempts != maxAttempts {
		t.Errorf("counter = %d, want %d", locked.FailedAttempts, maxAttempts)
	}
	if !locked.IsLocked(time.Now()) {
		t.Fatal("the account should be locked once the threshold is reached")
	}
	if remaining := locked.LockRemaining(time.Now()); remaining > lockFor || remaining < lockFor-time.Minute {
		t.Errorf("lock remaining = %s, want roughly %s", remaining, lockFor)
	}

	if err := st.ClearFailedAttempts(ctx, user.ID); err != nil {
		t.Fatalf("ClearFailedAttempts: %v", err)
	}
	cleared, err := st.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if cleared.FailedAttempts != 0 || cleared.LockedUntil != nil {
		t.Error("a successful login should clear both the counter and the lock")
	}
}

func TestConcurrentFailedAttemptsAreNotLost(t *testing.T) {
	st, ctx := newTestStore(t)
	user := newUser(t, st, ctx)

	// The increment and threshold check share one statement precisely so that
	// simultaneous failures cannot read-modify-write over each other.
	const attempts = 8
	errs := make(chan error, attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			_, err := st.RecordFailedAttempt(ctx, user.ID, 100, time.Minute)
			errs <- err
		}()
	}
	for i := 0; i < attempts; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("RecordFailedAttempt: %v", err)
		}
	}

	final, err := st.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if final.FailedAttempts != attempts {
		t.Errorf("counter = %d after %d concurrent failures, want %d",
			final.FailedAttempts, attempts, attempts)
	}
}

func TestTouchLastLoginReturnsThePreviousValue(t *testing.T) {
	st, ctx := newTestStore(t)
	user := newUser(t, st, ctx)

	first := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Millisecond)
	previous, err := st.TouchLastLogin(ctx, user.ID, first)
	if err != nil {
		t.Fatalf("TouchLastLogin: %v", err)
	}
	// "Last login" on a first sign-in has nothing to report.
	if previous != nil {
		t.Errorf("first login should report no previous login, got %v", previous)
	}

	second := time.Now().UTC().Truncate(time.Millisecond)
	previous, err = st.TouchLastLogin(ctx, user.ID, second)
	if err != nil {
		t.Fatalf("TouchLastLogin: %v", err)
	}
	if previous == nil {
		t.Fatal("the second login should report the first one")
	}
	if diff := previous.UTC().Sub(first); diff > time.Millisecond || diff < -time.Millisecond {
		t.Errorf("previous login = %s, want %s", previous.UTC(), first)
	}

	current, err := st.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if current.LastLoginAt == nil || current.LastLoginAt.UTC().Sub(second).Abs() > time.Millisecond {
		t.Error("last_login_at should now hold the most recent login")
	}

	if _, err := st.TouchLastLogin(ctx, 0, time.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("touching a missing user should give ErrNotFound, got %v", err)
	}
}

// ---------------------------------------------------------------- sessions

func TestSessionLifecycle(t *testing.T) {
	st, ctx := newTestStore(t)
	user := newUser(t, st, ctx)
	hash := tokenHash("lifecycle")

	session, err := st.CreateSession(ctx, user.ID, hash, 15*time.Minute, 12*time.Hour, "cli")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if !session.IsValid(time.Now()) {
		t.Fatal("a newly created session should be valid")
	}
	if session.ClientInfo != "cli" {
		t.Errorf("ClientInfo = %q, want %q", session.ClientInfo, "cli")
	}
	if !session.AbsoluteExpiresAt.After(session.IdleExpiresAt) {
		t.Error("the absolute deadline should sit beyond the idle deadline here")
	}

	loaded, loadedUser, err := st.GetSessionByTokenHash(ctx, hash)
	if err != nil {
		t.Fatalf("GetSessionByTokenHash: %v", err)
	}
	if loaded.ID != session.ID || loadedUser.ID != user.ID {
		t.Error("the session lookup returned the wrong row")
	}

	if _, _, err := st.GetSessionByTokenHash(ctx, []byte("no-such-token")); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown token should give ErrNotFound, got %v", err)
	}

	// Touching slides the idle deadline forward.
	touched, err := st.TouchSession(ctx, session.ID, 30*time.Minute)
	if err != nil {
		t.Fatalf("TouchSession: %v", err)
	}
	if !touched.IdleExpiresAt.After(session.IdleExpiresAt) {
		t.Errorf("idle deadline did not move: %s then %s", session.IdleExpiresAt, touched.IdleExpiresAt)
	}

	if err := st.RevokeSession(ctx, session.ID); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	if _, err := st.TouchSession(ctx, session.ID, 15*time.Minute); !errors.Is(err, ErrNotFound) {
		t.Errorf("a revoked session must not be touchable, got %v", err)
	}
	// Revoking twice is a no-op, not an error: logout should be idempotent.
	if err := st.RevokeSession(ctx, session.ID); err != nil {
		t.Errorf("RevokeSession should be idempotent, got %v", err)
	}

	revoked, _, err := st.GetSessionByTokenHash(ctx, hash)
	if err != nil {
		t.Fatalf("GetSessionByTokenHash after revoke: %v", err)
	}
	if revoked.RevokedAt == nil || revoked.IsValid(time.Now()) {
		t.Error("a revoked session should load but no longer be valid")
	}
}

func TestTouchSessionNeverExceedsTheAbsoluteDeadline(t *testing.T) {
	st, ctx := newTestStore(t)
	user := newUser(t, st, ctx)

	// A session near its hard ceiling: sliding must clamp to the ceiling rather
	// than extending past it, or an active user could stay signed in forever.
	session, err := st.CreateSession(ctx, user.ID, tokenHash("absolute-cap"),
		time.Minute, 30*time.Second, "cli")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	touched, err := st.TouchSession(ctx, session.ID, time.Hour)
	if err != nil {
		t.Fatalf("TouchSession: %v", err)
	}
	if touched.IdleExpiresAt.After(touched.AbsoluteExpiresAt) {
		t.Errorf("idle deadline %s was pushed past the absolute deadline %s",
			touched.IdleExpiresAt, touched.AbsoluteExpiresAt)
	}
	if !touched.IdleExpiresAt.Equal(touched.AbsoluteExpiresAt) {
		t.Errorf("idle deadline should be clamped to the cap: %s vs %s",
			touched.IdleExpiresAt, touched.AbsoluteExpiresAt)
	}
}

func TestTouchSessionRejectsAnExpiredSession(t *testing.T) {
	st, ctx := newTestStore(t)
	user := newUser(t, st, ctx)

	session, err := st.CreateSession(ctx, user.ID, tokenHash("expired"),
		15*time.Minute, 12*time.Hour, "cli")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Age the session rather than sleeping through a real timeout.
	_, err = st.pool.Exec(ctx,
		`UPDATE sessions SET idle_expires_at = now() - interval '1 second' WHERE id = $1`, session.ID)
	if err != nil {
		t.Fatalf("expire session: %v", err)
	}

	// The validity check lives inside the UPDATE, so a late command cannot
	// revive a session that has already lapsed.
	if _, err := st.TouchSession(ctx, session.ID, 15*time.Minute); !errors.Is(err, ErrNotFound) {
		t.Errorf("an expired session must not be touchable, got %v", err)
	}
}

func TestRevokeAllUserSessionsKeepsTheCurrentOne(t *testing.T) {
	st, ctx := newTestStore(t)
	user := newUser(t, st, ctx)

	current, err := st.CreateSession(ctx, user.ID, tokenHash("current"), time.Hour, 12*time.Hour, "cli")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := st.CreateSession(ctx, user.ID, tokenHash("other"),
			time.Hour, 12*time.Hour, "cli"); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
	}

	revoked, err := st.RevokeAllUserSessions(ctx, user.ID, current.ID)
	if err != nil {
		t.Fatalf("RevokeAllUserSessions: %v", err)
	}
	if revoked != 2 {
		t.Errorf("revoked %d sessions, want 2", revoked)
	}

	// The session that asked for the revocation must survive it.
	if _, err := st.TouchSession(ctx, current.ID, time.Hour); err != nil {
		t.Errorf("the excepted session should still be usable, got %v", err)
	}

	// Running it again finds nothing left to do.
	again, err := st.RevokeAllUserSessions(ctx, user.ID, current.ID)
	if err != nil {
		t.Fatalf("RevokeAllUserSessions: %v", err)
	}
	if again != 0 {
		t.Errorf("second call revoked %d sessions, want 0", again)
	}
}

func TestDeleteExpiredSessionsPrunesOnlyDeadRows(t *testing.T) {
	st, ctx := newTestStore(t)
	user := newUser(t, st, ctx)

	live, err := st.CreateSession(ctx, user.ID, tokenHash("live-prune"), time.Hour, 12*time.Hour, "cli")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	dead, err := st.CreateSession(ctx, user.ID, tokenHash("dead-prune"), time.Hour, 12*time.Hour, "cli")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if _, err := st.pool.Exec(ctx,
		`UPDATE sessions SET absolute_expires_at = now() - interval '48 hours' WHERE id = $1`, dead.ID); err != nil {
		t.Fatalf("age session: %v", err)
	}

	// Pruning is global by design — it only removes rows that are already dead,
	// which is exactly what the app does at startup.
	if _, err := st.DeleteExpiredSessions(ctx, 24*time.Hour); err != nil {
		t.Fatalf("DeleteExpiredSessions: %v", err)
	}

	if _, err := st.TouchSession(ctx, live.ID, time.Hour); err != nil {
		t.Errorf("the live session should have survived pruning, got %v", err)
	}
	var count int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE id = $1`, dead.ID).Scan(&count); err != nil {
		t.Fatalf("count pruned session: %v", err)
	}
	if count != 0 {
		t.Error("the long-expired session should have been pruned")
	}
}

// --------------------------------------------------------------------- MFA

func TestMFAEnrollmentAndRecoveryCodes(t *testing.T) {
	st, ctx := newTestStore(t)
	user := newUser(t, st, ctx)

	sealed := []byte("pretend-this-is-aes-gcm-ciphertext")
	hashes := [][]byte{[]byte("recovery-hash-1"), []byte("recovery-hash-2"), []byte("recovery-hash-3")}

	if err := st.SetMFASecret(ctx, user.ID, sealed, hashes); err != nil {
		t.Fatalf("SetMFASecret: %v", err)
	}

	enrolled, err := st.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if !enrolled.MFAEnabled {
		t.Error("MFA should be enabled after enrolment")
	}
	if string(enrolled.MFASecret) != string(sealed) {
		t.Error("the sealed secret did not round-trip through the database")
	}
	if enrolled.MFAEnrolledAt == nil {
		t.Error("mfa_enrolled_at should be set")
	}

	remaining, err := st.CountUnusedRecoveryCodes(ctx, user.ID)
	if err != nil {
		t.Fatalf("CountUnusedRecoveryCodes: %v", err)
	}
	if remaining != len(hashes) {
		t.Errorf("%d recovery codes stored, want %d", remaining, len(hashes))
	}

	// A recovery code is single-use: the second attempt with the same code must
	// fail, or a captured code would work forever.
	left, err := st.ConsumeRecoveryCode(ctx, user.ID, hashes[0])
	if err != nil {
		t.Fatalf("ConsumeRecoveryCode: %v", err)
	}
	if left != len(hashes)-1 {
		t.Errorf("%d codes left, want %d", left, len(hashes)-1)
	}
	if _, err := st.ConsumeRecoveryCode(ctx, user.ID, hashes[0]); !errors.Is(err, ErrNoRecoveryCode) {
		t.Errorf("reusing a spent code should give ErrNoRecoveryCode, got %v", err)
	}
	if _, err := st.ConsumeRecoveryCode(ctx, user.ID, []byte("never-issued")); !errors.Is(err, ErrNoRecoveryCode) {
		t.Errorf("an unknown code should give ErrNoRecoveryCode, got %v", err)
	}

	// Another user's code must not work here.
	other := newUser(t, st, ctx)
	if err := st.SetMFASecret(ctx, other.ID, sealed, [][]byte{[]byte("other-user-code")}); err != nil {
		t.Fatalf("SetMFASecret for the other user: %v", err)
	}
	if _, err := st.ConsumeRecoveryCode(ctx, user.ID, []byte("other-user-code")); !errors.Is(err, ErrNoRecoveryCode) {
		t.Errorf("another account's recovery code should not be accepted, got %v", err)
	}

	// Re-enrolling replaces the old codes rather than adding to them.
	if err := st.SetMFASecret(ctx, user.ID, sealed, [][]byte{[]byte("fresh-code")}); err != nil {
		t.Fatalf("re-enrol: %v", err)
	}
	remaining, err = st.CountUnusedRecoveryCodes(ctx, user.ID)
	if err != nil {
		t.Fatalf("CountUnusedRecoveryCodes: %v", err)
	}
	if remaining != 1 {
		t.Errorf("%d codes after re-enrolment, want 1", remaining)
	}
}

func TestDisableMFADestroysEverything(t *testing.T) {
	st, ctx := newTestStore(t)
	user := newUser(t, st, ctx)

	if err := st.SetMFASecret(ctx, user.ID, []byte("sealed"), [][]byte{[]byte("code-1"), []byte("code-2")}); err != nil {
		t.Fatalf("SetMFASecret: %v", err)
	}
	if _, err := st.ConsumeTOTPTimestep(ctx, user.ID, 100); err != nil {
		t.Fatalf("ConsumeTOTPTimestep: %v", err)
	}

	if err := st.DisableMFA(ctx, user.ID); err != nil {
		t.Fatalf("DisableMFA: %v", err)
	}

	disabled, err := st.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if disabled.MFAEnabled {
		t.Error("MFA should be off")
	}
	if disabled.MFASecret != nil {
		t.Error("the TOTP secret should be destroyed, not merely ignored")
	}
	if disabled.MFAEnrolledAt != nil || disabled.MFALastTimestep != nil {
		t.Error("enrolment metadata should be cleared so re-enrolling starts clean")
	}

	remaining, err := st.CountUnusedRecoveryCodes(ctx, user.ID)
	if err != nil {
		t.Fatalf("CountUnusedRecoveryCodes: %v", err)
	}
	if remaining != 0 {
		t.Errorf("%d recovery codes survived disabling MFA, want 0", remaining)
	}
}

func TestConsumeTOTPTimestepBlocksReplay(t *testing.T) {
	st, ctx := newTestStore(t)
	user := newUser(t, st, ctx)

	step := time.Now().Unix() / 30

	ok, err := st.ConsumeTOTPTimestep(ctx, user.ID, step)
	if err != nil {
		t.Fatalf("ConsumeTOTPTimestep: %v", err)
	}
	if !ok {
		t.Fatal("the first use of a timestep should be accepted")
	}

	// A TOTP code stays valid for its whole window; without this guard an
	// observed code could be replayed within the same 30 seconds.
	ok, err = st.ConsumeTOTPTimestep(ctx, user.ID, step)
	if err != nil {
		t.Fatalf("ConsumeTOTPTimestep: %v", err)
	}
	if ok {
		t.Error("replaying the same timestep should be rejected")
	}

	// An older code (inside the skew window) is also a replay.
	ok, err = st.ConsumeTOTPTimestep(ctx, user.ID, step-1)
	if err != nil {
		t.Fatalf("ConsumeTOTPTimestep: %v", err)
	}
	if ok {
		t.Error("an earlier timestep should be rejected")
	}

	// The next window is a genuinely new code.
	ok, err = st.ConsumeTOTPTimestep(ctx, user.ID, step+1)
	if err != nil {
		t.Fatalf("ConsumeTOTPTimestep: %v", err)
	}
	if !ok {
		t.Error("a later timestep should be accepted")
	}
}

func TestConcurrentTOTPUseAcceptsExactlyOne(t *testing.T) {
	st, ctx := newTestStore(t)
	user := newUser(t, st, ctx)

	step := time.Now().Unix() / 30
	const racers = 8

	results := make(chan bool, racers)
	for i := 0; i < racers; i++ {
		go func() {
			ok, err := st.ConsumeTOTPTimestep(ctx, user.ID, step)
			if err != nil {
				results <- false
				return
			}
			results <- ok
		}()
	}

	accepted := 0
	for i := 0; i < racers; i++ {
		if <-results {
			accepted++
		}
	}
	// The guard lives in the WHERE clause, so exactly one racer can win.
	if accepted != 1 {
		t.Errorf("%d concurrent uses of one code were accepted, want 1", accepted)
	}
}

func TestUpdatePasswordHash(t *testing.T) {
	st, ctx := newTestStore(t)
	user := newUser(t, st, ctx)

	if err := st.UpdatePasswordHash(ctx, user.ID, "$2a$04$brandnewhash"); err != nil {
		t.Fatalf("UpdatePasswordHash: %v", err)
	}
	updated, err := st.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if updated.PasswordHash != "$2a$04$brandnewhash" {
		t.Errorf("password hash = %q, want the new value", updated.PasswordHash)
	}
}

// ------------------------------------------------------------- audit trail

func TestAuthEventsAreRecordedNewestFirst(t *testing.T) {
	st, ctx := newTestStore(t)
	user := newUser(t, st, ctx)

	events := []struct {
		eventType string
		success   bool
		detail    string
	}{
		{models.EventRegister, true, "account created"},
		{models.EventLoginPassword, false, "wrong password"},
		{models.EventLockout, false, "too many attempts"},
		{models.EventLoginSuccess, true, "signed in"},
	}
	for _, e := range events {
		if err := st.RecordAuthEvent(ctx, &user.ID, user.Username, e.eventType, e.success, e.detail); err != nil {
			t.Fatalf("RecordAuthEvent: %v", err)
		}
	}

	got, err := st.RecentAuthEvents(ctx, user.ID, 10)
	if err != nil {
		t.Fatalf("RecentAuthEvents: %v", err)
	}
	if len(got) != len(events) {
		t.Fatalf("got %d events, want %d", len(got), len(events))
	}
	// Newest first, so `history` shows what just happened at the top. Rows
	// written inside the same clock tick are ordered by id as a tiebreak.
	if got[0].EventType != models.EventLoginSuccess {
		t.Errorf("first event = %q, want the most recent (%q)", got[0].EventType, models.EventLoginSuccess)
	}
	if got[0].Detail != "signed in" || !got[0].Success {
		t.Error("event details did not round-trip")
	}
	if got[len(got)-1].EventType != models.EventRegister {
		t.Errorf("last event = %q, want the oldest (%q)", got[len(got)-1].EventType, models.EventRegister)
	}

	limited, err := st.RecentAuthEvents(ctx, user.ID, 2)
	if err != nil {
		t.Fatalf("RecentAuthEvents: %v", err)
	}
	if len(limited) != 2 {
		t.Errorf("limit 2 returned %d events", len(limited))
	}
}

func TestAuthEventsAreScopedToOneUser(t *testing.T) {
	st, ctx := newTestStore(t)
	alice := newUser(t, st, ctx)
	bob := newUser(t, st, ctx)

	if err := st.RecordAuthEvent(ctx, &alice.ID, alice.Username, models.EventLoginSuccess, true, ""); err != nil {
		t.Fatalf("RecordAuthEvent: %v", err)
	}

	bobEvents, err := st.RecentAuthEvents(ctx, bob.ID, 10)
	if err != nil {
		t.Fatalf("RecentAuthEvents: %v", err)
	}
	if len(bobEvents) != 0 {
		t.Errorf("another account's history leaked: %d events", len(bobEvents))
	}
}

func TestRecordAuthEventAcceptsAnUnknownUser(t *testing.T) {
	st, ctx := newTestStore(t)

	// A failed login against a username that does not exist still has to be
	// auditable, so user_id is nullable and the username is denormalised.
	err := st.RecordAuthEvent(ctx, nil, "ghost-account", models.EventLoginPassword, false, "no such user")
	if err != nil {
		t.Fatalf("RecordAuthEvent with no user: %v", err)
	}

	_, cleanupErr := st.pool.Exec(context.Background(),
		`DELETE FROM auth_events WHERE user_id IS NULL AND username = 'ghost-account'`)
	if cleanupErr != nil {
		t.Logf("cleanup: %v", cleanupErr)
	}
}

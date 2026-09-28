// Package auth implements the authentication and session logic: registration,
// the two-stage login flow, account lockout, TOTP enrolment and verification.
//
// This package holds all security-relevant decisions. The CLI layer above it
// only collects input and renders results, so the rules can be reviewed and
// unit-tested in one place.
package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/elyashium/Containerized-CLI-Login-System-with-2FA/internal/config"
	"github.com/elyashium/Containerized-CLI-Login-System-with-2FA/internal/models"
	"github.com/elyashium/Containerized-CLI-Login-System-with-2FA/internal/security"
	"github.com/elyashium/Containerized-CLI-Login-System-with-2FA/internal/store"
)

// Errors surfaced to the CLI. The CLI maps these to user-facing messages, so
// the wording of an error here is not what the user finally sees.
var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrAccountLocked      = errors.New("account is temporarily locked")
	ErrUsernameTaken      = errors.New("username is already taken")
	ErrInvalidUsername    = errors.New("invalid username")
	ErrWeakPassword       = errors.New("password does not meet requirements")
	ErrMFARequired        = errors.New("a 2FA code is required")
	ErrInvalidTOTP        = errors.New("invalid or expired 2FA code")
	ErrTOTPReplayed       = errors.New("this 2FA code was already used")
	ErrMFAAlreadyEnabled  = errors.New("2FA is already enabled")
	ErrMFANotEnabled      = errors.New("2FA is not enabled")
	ErrSessionExpired     = errors.New("session has expired")
	ErrSessionInvalid     = errors.New("session is not valid")
	ErrPendingExpired     = errors.New("login timed out; please start again")
)

// LockedError carries the remaining lockout time so the CLI can tell the user
// when to try again.
type LockedError struct {
	RetryAfter time.Duration
}

func (e *LockedError) Error() string {
	return fmt.Sprintf("account is locked; try again in %s", formatDuration(e.RetryAfter))
}
func (e *LockedError) Is(target error) bool { return target == ErrAccountLocked }

// Service carries out authentication against the store.
type Service struct {
	store  *store.Store
	cfg    *config.Config
	cipher *security.Cipher
	log    *slog.Logger

	// now is injectable so tests can control time without sleeping.
	now func() time.Time
}

// NewService builds the auth service.
func NewService(st *store.Store, cfg *config.Config, log *slog.Logger) (*Service, error) {
	cipher, err := security.NewCipher(cfg.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("initialise secret encryption: %w", err)
	}
	return &Service{store: st, cfg: cfg, cipher: cipher, log: log, now: time.Now}, nil
}

// SetClock overrides the service clock. Test-only.
func (s *Service) SetClock(f func() time.Time) { s.now = f }

// Config exposes the active configuration for display purposes.
func (s *Service) Config() *config.Config { return s.cfg }

// ---------------------------------------------------------------- registration

// Register creates an account after validating the username and password.
func (s *Service) Register(ctx context.Context, username, password string) (*models.User, error) {
	username = strings.TrimSpace(username)
	if err := ValidateUsername(username); err != nil {
		return nil, err
	}
	if err := s.ValidatePassword(password, username); err != nil {
		return nil, err
	}

	hash, err := security.HashPassword(password, s.cfg.BcryptCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	user, err := s.store.CreateUser(ctx, username, hash)
	if errors.Is(err, store.ErrUsernameTaken) {
		return nil, ErrUsernameTaken
	}
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}

	s.audit(ctx, &user.ID, username, models.EventRegister, true, "account created")
	return user, nil
}

// UsernameRules describes the username constraints, shown in CLI help.
const UsernameRules = "3-32 characters, letters/digits/._- only, must start with a letter or digit"

// ValidateUsername enforces the username rules.
func ValidateUsername(username string) error {
	if len(username) < 3 || len(username) > 32 {
		return fmt.Errorf("%w: must be 3-32 characters", ErrInvalidUsername)
	}
	first := rune(username[0])
	if !unicode.IsLetter(first) && !unicode.IsDigit(first) {
		return fmt.Errorf("%w: must start with a letter or digit", ErrInvalidUsername)
	}
	for _, r := range username {
		// ASCII-only keeps usernames unambiguous: allowing Unicode invites
		// homoglyph impersonation (Cyrillic "а" vs Latin "a") unless we also
		// implement confusable-skeleton normalisation.
		isASCIILetter := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		isDigit := r >= '0' && r <= '9'
		if !isASCIILetter && !isDigit && r != '.' && r != '_' && r != '-' {
			return fmt.Errorf("%w: %q is not allowed (use letters, digits, '.', '_' or '-')",
				ErrInvalidUsername, r)
		}
	}
	return nil
}

// ValidatePassword enforces length and rejects passwords that are trivially
// related to the username or are well-known weak choices.
//
// It deliberately does not demand a fixed mix of character classes: NIST
// SP 800-63B finds composition rules push users toward predictable patterns,
// and length plus a denylist protects better.
func (s *Service) ValidatePassword(password, username string) error {
	if len(password) < s.cfg.MinPasswordLength {
		return fmt.Errorf("%w: must be at least %d characters", ErrWeakPassword, s.cfg.MinPasswordLength)
	}
	if len(password) > 72 {
		return fmt.Errorf("%w: must be at most 72 bytes", ErrWeakPassword)
	}
	lower := strings.ToLower(password)
	if username != "" && strings.Contains(lower, strings.ToLower(username)) {
		return fmt.Errorf("%w: must not contain your username", ErrWeakPassword)
	}
	if commonPasswords[lower] {
		return fmt.Errorf("%w: this password is too common", ErrWeakPassword)
	}
	if isSingleRepeatedRune(password) {
		return fmt.Errorf("%w: must not be a single repeated character", ErrWeakPassword)
	}
	return nil
}

// commonPasswords is a small denylist of passwords that are long enough to
// pass the length check but appear at the top of every breach corpus. A
// production system would check against a full breach dataset.
var commonPasswords = map[string]bool{
	"password":     true,
	"password1":    true,
	"password123":  true,
	"passw0rd123":  true,
	"123456789":    true,
	"1234567890":   true,
	"qwertyuiop":   true,
	"letmein123":   true,
	"iloveyou123":  true,
	"welcome123":   true,
	"admin123456":  true,
	"changeme123":  true,
	"password1234": true,
	"qwerty123456": true,
	"1qaz2wsx3edc": true,
}

func isSingleRepeatedRune(s string) bool {
	if s == "" {
		return false
	}
	runes := []rune(s)
	for _, r := range runes[1:] {
		if r != runes[0] {
			return false
		}
	}
	return true
}

// ------------------------------------------------------------------- login

// PendingLogin represents a login that passed the password stage and is
// waiting on a second factor.
type PendingLogin struct {
	UserID    int64
	Username  string
	ExpiresAt time.Time
}

// LoginResult is the outcome of a completed login.
type LoginResult struct {
	User           *models.User
	Session        *models.Session
	Token          string
	PreviousLogin  *time.Time
	RecoveryUsed   bool
	RecoveryLeft   int
	MFAWasRequired bool
}

// Authenticate performs stage one: username and password.
//
// On success it returns either a completed login (MFA off) or a PendingLogin
// (MFA on) that must be completed with CompleteMFALogin. The password stage
// never issues a session when MFA is enabled, so knowing the password alone
// grants nothing.
func (s *Service) Authenticate(ctx context.Context, username, password, clientInfo string) (*LoginResult, *PendingLogin, error) {
	username = strings.TrimSpace(username)
	now := s.now()

	user, err := s.store.GetUserByUsername(ctx, username)
	if errors.Is(err, store.ErrNotFound) {
		// Spend comparable CPU time so response latency does not reveal
		// whether the username exists.
		security.WasteTimeComparing(password)
		s.audit(ctx, nil, username, models.EventLoginPassword, false, "unknown username")
		return nil, nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, nil, fmt.Errorf("look up user: %w", err)
	}

	// Check the lock before verifying the password: a locked account must not
	// be a password-testing oracle.
	if user.IsLocked(now) {
		s.audit(ctx, &user.ID, username, models.EventLoginPassword, false, "attempt while locked")
		return nil, nil, &LockedError{RetryAfter: user.LockRemaining(now)}
	}

	if !security.VerifyPassword(user.PasswordHash, password) {
		locked, retryAfter := s.registerFailure(ctx, user, "wrong password")
		if locked {
			return nil, nil, &LockedError{RetryAfter: retryAfter}
		}
		return nil, nil, ErrInvalidCredentials
	}

	if user.MFAEnabled {
		s.audit(ctx, &user.ID, username, models.EventLoginPassword, true, "password accepted; awaiting 2FA")
		return nil, &PendingLogin{
			UserID:    user.ID,
			Username:  user.Username,
			ExpiresAt: now.Add(s.cfg.PendingLoginTTL),
		}, nil
	}

	s.audit(ctx, &user.ID, username, models.EventLoginPassword, true, "password accepted")
	result, err := s.completeLogin(ctx, user, clientInfo)
	if err != nil {
		return nil, nil, err
	}
	return result, nil, nil
}

// CompleteMFALogin performs stage two: a TOTP code or a recovery code.
func (s *Service) CompleteMFALogin(ctx context.Context, pending *PendingLogin, code, clientInfo string) (*LoginResult, error) {
	now := s.now()
	if now.After(pending.ExpiresAt) {
		return nil, ErrPendingExpired
	}

	user, err := s.store.GetUserByID(ctx, pending.UserID)
	if err != nil {
		return nil, fmt.Errorf("reload user: %w", err)
	}
	// Re-check the lock: concurrent failures elsewhere may have locked the
	// account since the password stage succeeded.
	if user.IsLocked(now) {
		return nil, &LockedError{RetryAfter: user.LockRemaining(now)}
	}
	if !user.MFAEnabled {
		// MFA was turned off in another session mid-login; nothing further to prove.
		return s.completeLogin(ctx, user, clientInfo)
	}

	code = strings.TrimSpace(code)

	// A recovery code is distinguishable by shape: TOTP codes are 6 digits.
	if looksLikeRecoveryCode(code) {
		return s.loginWithRecoveryCode(ctx, user, code, clientInfo)
	}

	// The AAD binds the ciphertext to this account, so a secret moved into
	// another user's row by a database-write attacker will not open.
	secret, err := s.cipher.DecryptString(user.MFASecret, security.UserAAD(user.ID))
	if err != nil {
		return nil, fmt.Errorf("decrypt 2FA secret: %w", err)
	}

	valid, timestep, err := s.validateTOTP(secret, code, now)
	if err != nil {
		return nil, err
	}
	if !valid {
		locked, retryAfter := s.registerFailure(ctx, user, "wrong 2FA code")
		if locked {
			return nil, &LockedError{RetryAfter: retryAfter}
		}
		return nil, ErrInvalidTOTP
	}

	// Reject reuse of a code that already authenticated a login.
	fresh, err := s.store.ConsumeTOTPTimestep(ctx, user.ID, timestep)
	if err != nil {
		return nil, err
	}
	if !fresh {
		locked, retryAfter := s.registerFailure(ctx, user, "replayed 2FA code")
		if locked {
			return nil, &LockedError{RetryAfter: retryAfter}
		}
		return nil, ErrTOTPReplayed
	}

	s.audit(ctx, &user.ID, user.Username, models.EventLoginTOTP, true, "2FA code accepted")
	result, err := s.completeLogin(ctx, user, clientInfo)
	if err != nil {
		return nil, err
	}
	result.MFAWasRequired = true
	return result, nil
}

// looksLikeRecoveryCode distinguishes a recovery code from a 6-digit TOTP.
func looksLikeRecoveryCode(code string) bool {
	normalized := security.NormalizeRecoveryCode(code)
	if len(normalized) != 10 {
		return false
	}
	for _, r := range normalized {
		if !strings.ContainsRune(recoveryAlphabet, r) {
			return false
		}
	}
	return true
}

const recoveryAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

func (s *Service) loginWithRecoveryCode(ctx context.Context, user *models.User, code, clientInfo string) (*LoginResult, error) {
	remaining, err := s.store.ConsumeRecoveryCode(ctx, user.ID, security.HashRecoveryCode(code))
	if errors.Is(err, store.ErrNoRecoveryCode) {
		locked, retryAfter := s.registerFailure(ctx, user, "wrong recovery code")
		if locked {
			return nil, &LockedError{RetryAfter: retryAfter}
		}
		return nil, ErrInvalidTOTP
	}
	if err != nil {
		return nil, err
	}

	s.audit(ctx, &user.ID, user.Username, models.EventLoginRecovery, true,
		fmt.Sprintf("recovery code used; %d remaining", remaining))

	result, err := s.completeLogin(ctx, user, clientInfo)
	if err != nil {
		return nil, err
	}
	result.RecoveryUsed = true
	result.RecoveryLeft = remaining
	result.MFAWasRequired = true
	return result, nil
}

// validateTOTP checks a code and returns the timestep it matched, so the
// caller can record it and prevent replay.
func (s *Service) validateTOTP(secret, code string, now time.Time) (valid bool, timestep int64, err error) {
	opts := totp.ValidateOpts{
		Period:    30,
		Skew:      s.cfg.TOTPSkew,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	}
	ok, err := totp.ValidateCustom(code, secret, now.UTC(), opts)
	if err != nil {
		// A malformed code is a failed attempt, not an internal error.
		return false, 0, nil
	}
	if !ok {
		return false, 0, nil
	}

	// Identify which step matched so it can be marked as consumed. Checking
	// the current step first makes the common case a single comparison.
	current := now.UTC().Unix() / 30
	candidates := []int64{current}
	for i := int64(1); i <= int64(s.cfg.TOTPSkew); i++ {
		candidates = append(candidates, current-i, current+i)
	}
	for _, step := range candidates {
		stepTime := time.Unix(step*30, 0).UTC()
		exact := totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
		if matched, verr := totp.ValidateCustom(code, secret, stepTime, exact); verr == nil && matched {
			return true, step, nil
		}
	}
	// Validated overall but no exact step matched: treat as current step
	// rather than silently skipping replay protection.
	return true, current, nil
}

// completeLogin resets lockout state, records the login and opens a session.
func (s *Service) completeLogin(ctx context.Context, user *models.User, clientInfo string) (*LoginResult, error) {
	now := s.now()

	if err := s.store.ClearFailedAttempts(ctx, user.ID); err != nil {
		return nil, err
	}

	previousLogin, err := s.store.TouchLastLogin(ctx, user.ID, now)
	if err != nil {
		return nil, err
	}

	token, err := security.NewSessionToken()
	if err != nil {
		return nil, err
	}
	session, err := s.store.CreateSession(ctx, user.ID, security.HashToken(token),
		s.cfg.SessionIdleTimeout, s.cfg.SessionAbsoluteTimeout, clientInfo)
	if err != nil {
		return nil, err
	}

	// Reflect the writes in the returned copy so callers need not re-query.
	user.FailedAttempts = 0
	user.LockedUntil = nil
	user.LastLoginAt = &now

	s.audit(ctx, &user.ID, user.Username, models.EventLoginSuccess, true, "session opened")

	return &LoginResult{
		User:          user,
		Session:       session,
		Token:         token,
		PreviousLogin: previousLogin,
	}, nil
}

// registerFailure increments the failure counter and reports whether the
// account is now locked.
func (s *Service) registerFailure(ctx context.Context, user *models.User, reason string) (locked bool, retryAfter time.Duration) {
	updated, err := s.store.RecordFailedAttempt(ctx, user.ID, s.cfg.MaxFailedAttempts, s.cfg.LockoutDuration)
	if err != nil {
		// Never let bookkeeping failure turn into a successful login; the
		// caller still treats this as a failed attempt.
		s.log.Error("could not record failed attempt", "error", err, "user_id", user.ID)
		s.audit(ctx, &user.ID, user.Username, models.EventLoginPassword, false, reason)
		return false, 0
	}

	s.audit(ctx, &user.ID, user.Username, models.EventLoginPassword, false,
		fmt.Sprintf("%s (%d/%d)", reason, updated.FailedAttempts, s.cfg.MaxFailedAttempts))

	now := s.now()
	if updated.IsLocked(now) {
		remaining := updated.LockRemaining(now)
		s.audit(ctx, &user.ID, user.Username, models.EventLockout, false,
			fmt.Sprintf("locked for %s after %d failed attempts",
				formatDuration(remaining), updated.FailedAttempts))
		return true, remaining
	}
	return false, 0
}

// AttemptsRemaining reports how many further failures the account tolerates.
func (s *Service) AttemptsRemaining(user *models.User) int {
	remaining := s.cfg.MaxFailedAttempts - user.FailedAttempts
	if remaining < 0 {
		return 0
	}
	return remaining
}

// ----------------------------------------------------------------- sessions

// ResolveSession validates a token and slides the idle deadline forward.
func (s *Service) ResolveSession(ctx context.Context, token string) (*models.Session, *models.User, error) {
	if token == "" {
		return nil, nil, ErrSessionInvalid
	}
	hash := security.HashToken(token)

	session, user, err := s.store.GetSessionByTokenHash(ctx, hash)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, ErrSessionInvalid
	}
	if err != nil {
		return nil, nil, err
	}

	now := s.now()
	if session.RevokedAt != nil {
		return nil, nil, ErrSessionInvalid
	}
	if !session.IsValid(now) {
		s.audit(ctx, &user.ID, user.Username, models.EventSessionExpired, false, "session expired")
		return nil, nil, ErrSessionExpired
	}

	// TouchSession re-checks validity in SQL, closing the gap between the
	// read above and this write.
	refreshed, err := s.store.TouchSession(ctx, session.ID, s.cfg.SessionIdleTimeout)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, ErrSessionExpired
	}
	if err != nil {
		return nil, nil, err
	}
	return refreshed, user, nil
}

// Logout revokes a session.
func (s *Service) Logout(ctx context.Context, session *models.Session, user *models.User) error {
	if err := s.store.RevokeSession(ctx, session.ID); err != nil {
		return err
	}
	s.audit(ctx, &user.ID, user.Username, models.EventLogout, true, "session closed")
	return nil
}

// --------------------------------------------------------------------- MFA

// MFAEnrollment is an in-progress 2FA setup, not yet persisted.
type MFAEnrollment struct {
	Secret        string
	URI           string
	RecoveryCodes []string
}

// BeginMFAEnrollment generates a secret and provisioning URI without saving
// anything. The secret is only stored once the user proves they can generate
// a valid code, so a failed setup cannot lock them out.
func (s *Service) BeginMFAEnrollment(ctx context.Context, user *models.User) (*MFAEnrollment, error) {
	if user.MFAEnabled {
		return nil, ErrMFAAlreadyEnabled
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.cfg.TOTPIssuer,
		AccountName: user.Username,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
		SecretSize:  20,
	})
	if err != nil {
		return nil, fmt.Errorf("generate 2FA secret: %w", err)
	}

	codes := make([]string, 0, recoveryCodeCount)
	for i := 0; i < recoveryCodeCount; i++ {
		code, err := security.NewRecoveryCode()
		if err != nil {
			return nil, err
		}
		codes = append(codes, code)
	}

	return &MFAEnrollment{Secret: key.Secret(), URI: key.URL(), RecoveryCodes: codes}, nil
}

// recoveryCodeCount is how many single-use codes are issued at enrolment.
const recoveryCodeCount = 8

// ConfirmMFAEnrollment verifies a code against the pending secret and, only on
// success, persists it and the recovery codes.
func (s *Service) ConfirmMFAEnrollment(ctx context.Context, user *models.User, enrollment *MFAEnrollment, code string) error {
	if user.MFAEnabled {
		return ErrMFAAlreadyEnabled
	}

	valid, timestep, err := s.validateTOTP(enrollment.Secret, strings.TrimSpace(code), s.now())
	if err != nil {
		return err
	}
	if !valid {
		return ErrInvalidTOTP
	}

	sealed, err := s.cipher.EncryptString(enrollment.Secret, security.UserAAD(user.ID))
	if err != nil {
		return fmt.Errorf("encrypt 2FA secret: %w", err)
	}

	hashes := make([][]byte, 0, len(enrollment.RecoveryCodes))
	for _, c := range enrollment.RecoveryCodes {
		hashes = append(hashes, security.HashRecoveryCode(c))
	}

	if err := s.store.SetMFASecret(ctx, user.ID, sealed, hashes); err != nil {
		return err
	}
	// Burn the confirming code so it cannot immediately be replayed as a login.
	if _, err := s.store.ConsumeTOTPTimestep(ctx, user.ID, timestep); err != nil {
		s.log.Warn("could not record enrolment timestep", "error", err, "user_id", user.ID)
	}

	user.MFAEnabled = true
	now := s.now()
	user.MFAEnrolledAt = &now

	s.audit(ctx, &user.ID, user.Username, models.EventEnable2FA, true, "2FA enabled")
	return nil
}

// DisableMFA turns 2FA off after re-verifying the user's password.
//
// Requiring the password means someone who walks up to an unlocked terminal
// cannot strip the second factor off the account.
func (s *Service) DisableMFA(ctx context.Context, user *models.User, password string) error {
	if !user.MFAEnabled {
		return ErrMFANotEnabled
	}
	if !security.VerifyPassword(user.PasswordHash, password) {
		s.audit(ctx, &user.ID, user.Username, models.EventDisable2FA, false, "wrong password")
		return ErrInvalidCredentials
	}
	if err := s.store.DisableMFA(ctx, user.ID); err != nil {
		return err
	}

	user.MFAEnabled = false
	user.MFASecret = nil
	user.MFAEnrolledAt = nil

	s.audit(ctx, &user.ID, user.Username, models.EventDisable2FA, true, "2FA disabled")
	return nil
}

// RevokeOtherSessions ends every other live session for the user, used after a
// security-relevant change.
func (s *Service) RevokeOtherSessions(ctx context.Context, userID, keepSessionID int64) (int64, error) {
	return s.store.RevokeAllUserSessions(ctx, userID, keepSessionID)
}

// RecoveryCodesRemaining reports how many unused recovery codes are left.
func (s *Service) RecoveryCodesRemaining(ctx context.Context, userID int64) (int, error) {
	return s.store.CountUnusedRecoveryCodes(ctx, userID)
}

// RecentEvents returns audit history for the `history` command.
func (s *Service) RecentEvents(ctx context.Context, userID int64, limit int) ([]models.AuthEvent, error) {
	return s.store.RecentAuthEvents(ctx, userID, limit)
}

// audit writes an audit row, logging rather than failing if it cannot: losing
// an audit line must not break a login.
func (s *Service) audit(ctx context.Context, userID *int64, username, eventType string, success bool, detail string) {
	// Use a detached context so an event is still recorded when the caller's
	// context is already cancelled (e.g. the user hit Ctrl-C).
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()

	if err := s.store.RecordAuthEvent(writeCtx, userID, username, eventType, success, detail); err != nil {
		s.log.Warn("could not record auth event",
			"error", err, "event", eventType, "username", username)
	}
}

// formatDuration renders a duration for humans: "2m 30s" rather than "2m30s".
func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	sec := int(d.Seconds()) % 60

	var parts []string
	if h > 0 {
		parts = append(parts, fmt.Sprintf("%dh", h))
	}
	if m > 0 {
		parts = append(parts, fmt.Sprintf("%dm", m))
	}
	if sec > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%ds", sec))
	}
	return strings.Join(parts, " ")
}

// FormatDuration exposes the human-friendly duration formatting to the CLI.
func FormatDuration(d time.Duration) string { return formatDuration(d) }

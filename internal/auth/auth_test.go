package auth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/elyashium/Containerized-CLI-Login-System-with-2FA/internal/config"
	"github.com/elyashium/Containerized-CLI-Login-System-with-2FA/internal/models"
)

// newTestService builds a Service with no store. Every test here exercises
// logic that never touches the database; store-backed flows are covered by the
// integration test in internal/store.
func newTestService(t *testing.T) *Service {
	t.Helper()
	return &Service{
		cfg: &config.Config{
			MinPasswordLength:      10,
			MaxFailedAttempts:      5,
			LockoutDuration:        15 * time.Minute,
			SessionIdleTimeout:     15 * time.Minute,
			SessionAbsoluteTimeout: 12 * time.Hour,
			PendingLoginTTL:        2 * time.Minute,
			TOTPSkew:               1,
			TOTPIssuer:             "CLI Login Test",
		},
		now: time.Now,
	}
}

// ------------------------------------------------------------- username rules

func TestValidateUsername(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"simple", "alice", false},
		{"digits", "user2024", false},
		{"dots and dashes", "a.b-c_d", false},
		{"minimum length", "abc", false},
		{"maximum length", strings.Repeat("a", 32), false},
		{"starts with a digit", "1user", false},

		{"too short", "ab", true},
		{"too long", strings.Repeat("a", 33), true},
		{"empty", "", true},
		{"leading dot", ".alice", true},
		{"leading dash", "-alice", true},
		{"leading underscore", "_alice", true},
		{"contains a space", "alice smith", true},
		{"contains an at sign", "alice@example.com", true},
		{"contains a slash", "alice/bob", true},
		{"contains a quote", "alice'--", true},
		{"contains a null byte", "alice\x00", true},
		// Unicode is rejected on purpose: "аlice" with a Cyrillic а renders
		// identically to "alice" and would enable impersonation.
		{"cyrillic homoglyph", "аlice", true},
		{"emoji", "alice\U0001F600", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateUsername(tc.input)
			if tc.wantErr && err == nil {
				t.Errorf("ValidateUsername(%q) = nil, want an error", tc.input)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ValidateUsername(%q) = %v, want nil", tc.input, err)
			}
			if tc.wantErr && err != nil && !errors.Is(err, ErrInvalidUsername) {
				t.Errorf("ValidateUsername(%q) error does not wrap ErrInvalidUsername: %v", tc.input, err)
			}
		})
	}
}

// ------------------------------------------------------------- password rules

func TestValidatePassword(t *testing.T) {
	s := newTestService(t)

	cases := []struct {
		name     string
		password string
		username string
		wantErr  bool
	}{
		{"long passphrase", "correct horse battery staple", "alice", false},
		{"exactly the minimum", "abcdefghij", "alice", false},
		{"no composition rules required", "aaaaaaaaab", "alice", false},

		{"too short", "short", "alice", true},
		{"empty", "", "alice", true},
		{"one below the minimum", "abcdefghi", "alice", true},
		{"over bcrypt's limit", strings.Repeat("a", 73), "alice", true},
		{"contains the username", "alice-is-great", "alice", true},
		{"contains the username in mixed case", "xxALICExxyy", "alice", true},
		{"common password", "password123", "alice", true},
		{"common password in mixed case", "Password123", "alice", true},
		{"single repeated character", strings.Repeat("a", 20), "bob", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := s.ValidatePassword(tc.password, tc.username)
			if tc.wantErr && err == nil {
				t.Errorf("ValidatePassword(%q, %q) = nil, want an error", tc.password, tc.username)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ValidatePassword(%q, %q) = %v, want nil", tc.password, tc.username, err)
			}
			if tc.wantErr && err != nil && !errors.Is(err, ErrWeakPassword) {
				t.Errorf("error does not wrap ErrWeakPassword: %v", err)
			}
		})
	}
}

func TestValidatePasswordHonoursConfiguredLength(t *testing.T) {
	s := newTestService(t)
	s.cfg.MinPasswordLength = 16

	if err := s.ValidatePassword("abcdefghij", "alice"); err == nil {
		t.Error("a 10-character password should be rejected when the minimum is 16")
	}
	if err := s.ValidatePassword("abcdefghijklmnop", "alice"); err != nil {
		t.Errorf("a 16-character password should be accepted: %v", err)
	}
}

// -------------------------------------------------------------------- TOTP

func TestValidateTOTPAcceptsCurrentCode(t *testing.T) {
	s := newTestService(t)
	secret := newTestSecret(t)
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	code, err := totp.GenerateCode(secret, now)
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	valid, timestep, err := s.validateTOTP(secret, code, now)
	if err != nil {
		t.Fatalf("validateTOTP: %v", err)
	}
	if !valid {
		t.Fatal("the current code was rejected")
	}
	if want := now.Unix() / 30; timestep != want {
		t.Errorf("timestep = %d, want %d", timestep, want)
	}
}

func TestValidateTOTPRejectsWrongCodes(t *testing.T) {
	s := newTestService(t)
	secret := newTestSecret(t)
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	correct, err := totp.GenerateCode(secret, now)
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	for _, code := range []string{"000000", "123456", "", "abcdef", "12345", "1234567", correct + "0"} {
		if code == correct {
			continue
		}
		valid, _, err := s.validateTOTP(secret, code, now)
		if err != nil {
			t.Errorf("validateTOTP(%q) returned an error rather than a plain rejection: %v", code, err)
		}
		if valid {
			t.Errorf("validateTOTP accepted %q", code)
		}
	}
}

func TestValidateTOTPSkewWindow(t *testing.T) {
	s := newTestService(t) // skew 1 => previous, current and next step accepted
	secret := newTestSecret(t)
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name       string
		offsetStep int64
		wantValid  bool
	}{
		{"previous step", -1, true},
		{"current step", 0, true},
		{"next step", 1, true},
		{"two steps behind", -2, false},
		{"two steps ahead", 2, false},
		{"ten minutes ago", -20, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			codeTime := now.Add(time.Duration(tc.offsetStep) * 30 * time.Second)
			code, err := totp.GenerateCode(secret, codeTime)
			if err != nil {
				t.Fatalf("GenerateCode: %v", err)
			}

			valid, timestep, err := s.validateTOTP(secret, code, now)
			if err != nil {
				t.Fatalf("validateTOTP: %v", err)
			}
			if valid != tc.wantValid {
				t.Fatalf("validateTOTP = %v, want %v", valid, tc.wantValid)
			}
			if !tc.wantValid {
				return
			}
			// The reported timestep is what gets recorded to prevent replay, so
			// it must name the step the code actually belongs to.
			if want := codeTime.Unix() / 30; timestep != want {
				t.Errorf("timestep = %d, want %d", timestep, want)
			}
		})
	}
}

func TestValidateTOTPWithZeroSkewIsStrict(t *testing.T) {
	s := newTestService(t)
	s.cfg.TOTPSkew = 0
	secret := newTestSecret(t)
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	previous, err := totp.GenerateCode(secret, now.Add(-30*time.Second))
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if valid, _, _ := s.validateTOTP(secret, previous, now); valid {
		t.Error("with skew 0 the previous step's code must be rejected")
	}
}

func TestValidateTOTPRejectsAnotherUsersSecret(t *testing.T) {
	s := newTestService(t)
	mine := newTestSecret(t)
	theirs := newTestSecret(t)
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	code, err := totp.GenerateCode(theirs, now)
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if valid, _, _ := s.validateTOTP(mine, code, now); valid {
		t.Error("a code generated from a different secret was accepted")
	}
}

// newTestSecret returns a base32 TOTP secret produced the same way enrolment
// does, so the tests exercise the real format.
func newTestSecret(t *testing.T) string {
	t.Helper()
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "CLI Login Test",
		AccountName: "tester",
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
		SecretSize:  20,
	})
	if err != nil {
		t.Fatalf("totp.Generate: %v", err)
	}
	return key.Secret()
}

// --------------------------------------------------------------- recovery codes

func TestLooksLikeRecoveryCode(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		{"ABCDE-FGHJK", true},
		{"abcde-fghjk", true},
		{"ABCDEFGHJK", true},
		{" ABCDE-FGHJK ", true},

		// Six digits is a TOTP code, so it must not be routed to the recovery
		// code path.
		{"123456", false},
		{"000000", false},
		// Wrong length.
		{"ABCDE", false},
		{"ABCDE-FGHJKL", false},
		{"", false},
		// 0 and I are excluded from the alphabet as ambiguous.
		{"ABCDE-FGHI0", false},
	}
	for _, tc := range cases {
		if got := looksLikeRecoveryCode(tc.input); got != tc.want {
			t.Errorf("looksLikeRecoveryCode(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

// ------------------------------------------------------------------- lockout

func TestAttemptsRemaining(t *testing.T) {
	s := newTestService(t) // MaxFailedAttempts 5
	cases := []struct{ failed, want int }{
		{0, 5}, {1, 4}, {4, 1}, {5, 0},
		{9, 0}, // never negative
	}
	for _, tc := range cases {
		user := &models.User{FailedAttempts: tc.failed}
		if got := s.AttemptsRemaining(user); got != tc.want {
			t.Errorf("AttemptsRemaining with %d failures = %d, want %d", tc.failed, got, tc.want)
		}
	}
}

func TestLockedErrorMatchesSentinel(t *testing.T) {
	// The CLI matches on ErrAccountLocked while still needing the retry-after
	// value, so LockedError must satisfy errors.Is and errors.As.
	err := error(&LockedError{RetryAfter: 90 * time.Second})

	if !errors.Is(err, ErrAccountLocked) {
		t.Error("LockedError should match ErrAccountLocked")
	}
	if errors.Is(err, ErrInvalidCredentials) {
		t.Error("LockedError should not match ErrInvalidCredentials")
	}

	var locked *LockedError
	if !errors.As(err, &locked) {
		t.Fatal("errors.As failed to extract LockedError")
	}
	if locked.RetryAfter != 90*time.Second {
		t.Errorf("RetryAfter = %s, want 1m30s", locked.RetryAfter)
	}
	if !strings.Contains(err.Error(), "1m 30s") {
		t.Errorf("error message should carry a human duration, got %q", err.Error())
	}
}

// ------------------------------------------------------------------ sessions

func TestPendingLoginExpiry(t *testing.T) {
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	pending := &PendingLogin{UserID: 1, Username: "alice", ExpiresAt: base.Add(2 * time.Minute)}

	if base.After(pending.ExpiresAt) {
		t.Error("a freshly created pending login should not be expired")
	}
	if !base.Add(3 * time.Minute).After(pending.ExpiresAt) {
		t.Error("a pending login should expire after its TTL")
	}
}

// ---------------------------------------------------------------- formatting

func TestFormatDuration(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{0, "0s"},
		{-5 * time.Second, "0s"},
		{30 * time.Second, "30s"},
		{time.Minute, "1m"},
		{90 * time.Second, "1m 30s"},
		{15 * time.Minute, "15m"},
		{time.Hour, "1h"},
		{90 * time.Minute, "1h 30m"},
		{12 * time.Hour, "12h"},
		{2*time.Hour + 3*time.Minute + 4*time.Second, "2h 3m 4s"},
		{1500 * time.Millisecond, "2s"}, // rounds to the nearest second
	}
	for _, tc := range cases {
		if got := FormatDuration(tc.in); got != tc.want {
			t.Errorf("FormatDuration(%s) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestIsSingleRepeatedRune(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"a", true},
		{"aaaa", true},
		{"aaab", false},
		{"abab", false},
		{"ééé", true}, // multi-byte runes compare as runes, not bytes
	}
	for _, tc := range cases {
		if got := isSingleRepeatedRune(tc.in); got != tc.want {
			t.Errorf("isSingleRepeatedRune(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

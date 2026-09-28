package config

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// optionalVars is every knob Load reads beyond the two required ones. Tests
// clear them so an ambient .env or shell export cannot change what a default
// is expected to be.
var optionalVars = []string{
	"DB_CONNECT_TIMEOUT", "BCRYPT_COST", "MAX_FAILED_ATTEMPTS", "LOCKOUT_DURATION",
	"SESSION_IDLE_TIMEOUT", "SESSION_ABSOLUTE_TIMEOUT", "SESSION_PERSIST",
	"PENDING_LOGIN_TTL", "MIN_PASSWORD_LENGTH", "TOTP_SKEW", "TOTP_ISSUER",
	"STATE_DIR",
}

// setMinimalEnv sets exactly what Load requires and clears everything else, so
// each test can vary one thing at a time.
func setMinimalEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DATABASE_URL", "postgres://app:secret@db:5432/clilogin?sslmode=disable")
	t.Setenv("APP_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(make([]byte, EncryptionKeySize)))
	for _, key := range optionalVars {
		t.Setenv(key, "")
	}
}

func TestLoadAppliesDefaults(t *testing.T) {
	setMinimalEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	checks := []struct {
		name string
		got  any
		want any
	}{
		{"BcryptCost", cfg.BcryptCost, 12},
		{"MaxFailedAttempts", cfg.MaxFailedAttempts, 5},
		{"LockoutDuration", cfg.LockoutDuration, 15 * time.Minute},
		{"SessionIdleTimeout", cfg.SessionIdleTimeout, 15 * time.Minute},
		{"SessionAbsoluteTimeout", cfg.SessionAbsoluteTimeout, 12 * time.Hour},
		{"SessionPersist", cfg.SessionPersist, true},
		{"PendingLoginTTL", cfg.PendingLoginTTL, 2 * time.Minute},
		{"MinPasswordLength", cfg.MinPasswordLength, 10},
		{"TOTPSkew", cfg.TOTPSkew, uint(1)},
		{"TOTPIssuer", cfg.TOTPIssuer, "CLI Login"},
		{"DBConnectTimeout", cfg.DBConnectTimeout, 30 * time.Second},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}

	// The defaults must be internally consistent, or Load would have rejected
	// its own fallbacks the first time someone ran the app with a bare .env.
	if cfg.SessionIdleTimeout > cfg.SessionAbsoluteTimeout {
		t.Error("the default idle timeout exceeds the default absolute cap")
	}
	if len(cfg.EncryptionKey) != EncryptionKeySize {
		t.Errorf("EncryptionKey is %d bytes, want %d", len(cfg.EncryptionKey), EncryptionKeySize)
	}
	if cfg.StateDir == "" {
		t.Error("StateDir should fall back to a default rather than being empty")
	}
}

func TestLoadReadsOverrides(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("BCRYPT_COST", "10")
	t.Setenv("MAX_FAILED_ATTEMPTS", "3")
	t.Setenv("LOCKOUT_DURATION", "30s")
	t.Setenv("SESSION_IDLE_TIMEOUT", "1m")
	t.Setenv("SESSION_ABSOLUTE_TIMEOUT", "2h")
	t.Setenv("SESSION_PERSIST", "false")
	t.Setenv("MIN_PASSWORD_LENGTH", "16")
	t.Setenv("TOTP_SKEW", "0")
	t.Setenv("TOTP_ISSUER", "Acme Corp")
	t.Setenv("STATE_DIR", "/tmp/cli-login-test")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.BcryptCost != 10 {
		t.Errorf("BcryptCost = %d, want 10", cfg.BcryptCost)
	}
	if cfg.MaxFailedAttempts != 3 {
		t.Errorf("MaxFailedAttempts = %d, want 3", cfg.MaxFailedAttempts)
	}
	if cfg.LockoutDuration != 30*time.Second {
		t.Errorf("LockoutDuration = %s, want 30s", cfg.LockoutDuration)
	}
	if cfg.SessionIdleTimeout != time.Minute {
		t.Errorf("SessionIdleTimeout = %s, want 1m", cfg.SessionIdleTimeout)
	}
	if cfg.SessionAbsoluteTimeout != 2*time.Hour {
		t.Errorf("SessionAbsoluteTimeout = %s, want 2h", cfg.SessionAbsoluteTimeout)
	}
	if cfg.SessionPersist {
		t.Error("SESSION_PERSIST=false was not honoured")
	}
	if cfg.MinPasswordLength != 16 {
		t.Errorf("MinPasswordLength = %d, want 16", cfg.MinPasswordLength)
	}
	if cfg.TOTPSkew != 0 {
		t.Errorf("TOTPSkew = %d, want 0", cfg.TOTPSkew)
	}
	if cfg.TOTPIssuer != "Acme Corp" {
		t.Errorf("TOTPIssuer = %q, want %q", cfg.TOTPIssuer, "Acme Corp")
	}
	if cfg.StateDir != "/tmp/cli-login-test" {
		t.Errorf("StateDir = %q, want /tmp/cli-login-test", cfg.StateDir)
	}
}

func TestLoadTrimsSurroundingWhitespace(t *testing.T) {
	// Values copied out of a .env file often carry a trailing space; treating
	// " 20m" as unparseable would be a confusing failure.
	setMinimalEnv(t)
	t.Setenv("LOCKOUT_DURATION", "  20m  ")
	t.Setenv("TOTP_ISSUER", "  Acme  ")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LockoutDuration != 20*time.Minute {
		t.Errorf("LockoutDuration = %s, want 20m", cfg.LockoutDuration)
	}
	if cfg.TOTPIssuer != "Acme" {
		t.Errorf("TOTPIssuer = %q, want %q", cfg.TOTPIssuer, "Acme")
	}
}

func TestLoadRejectsInvalidValues(t *testing.T) {
	cases := []struct {
		name     string
		env      map[string]string
		mentions string
	}{
		{"missing database url", map[string]string{"DATABASE_URL": ""}, "DATABASE_URL"},
		{"missing encryption key", map[string]string{"APP_ENCRYPTION_KEY": ""}, "APP_ENCRYPTION_KEY"},
		{"short encryption key", map[string]string{"APP_ENCRYPTION_KEY": "c2hvcnQ="}, "APP_ENCRYPTION_KEY"},
		{"non-numeric bcrypt cost", map[string]string{"BCRYPT_COST": "high"}, "BCRYPT_COST"},
		{"bcrypt cost too low", map[string]string{"BCRYPT_COST": "4"}, "BCRYPT_COST"},
		{"bcrypt cost too high", map[string]string{"BCRYPT_COST": "40"}, "BCRYPT_COST"},
		{"zero lockout threshold", map[string]string{"MAX_FAILED_ATTEMPTS": "0"}, "MAX_FAILED_ATTEMPTS"},
		{"unparseable duration", map[string]string{"LOCKOUT_DURATION": "15 minutes"}, "LOCKOUT_DURATION"},
		{"negative lockout", map[string]string{"LOCKOUT_DURATION": "-5m"}, "LOCKOUT_DURATION"},
		{"unparseable boolean", map[string]string{"SESSION_PERSIST": "yes please"}, "SESSION_PERSIST"},
		{"password minimum below 8", map[string]string{"MIN_PASSWORD_LENGTH": "4"}, "MIN_PASSWORD_LENGTH"},
		{"skew out of range", map[string]string{"TOTP_SKEW": "99"}, "TOTP_SKEW"},
		{"idle longer than the absolute cap", map[string]string{
			"SESSION_IDLE_TIMEOUT":     "24h",
			"SESSION_ABSOLUTE_TIMEOUT": "1h",
		}, "SESSION_IDLE_TIMEOUT"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setMinimalEnv(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}

			cfg, err := Load()
			if err == nil {
				t.Fatal("Load succeeded, want an error")
			}
			if cfg != nil {
				t.Error("Load returned a config alongside an error; callers would use a half-validated value")
			}
			if !strings.Contains(err.Error(), tc.mentions) {
				t.Errorf("error should name %s, got: %v", tc.mentions, err)
			}
		})
	}
}

func TestLoadReportsEveryProblemAtOnce(t *testing.T) {
	// One run should surface every misconfiguration, so an operator can fix a
	// broken deployment in a single pass rather than one error at a time.
	setMinimalEnv(t)
	t.Setenv("DATABASE_URL", "")
	t.Setenv("APP_ENCRYPTION_KEY", "")
	t.Setenv("BCRYPT_COST", "2")

	_, err := Load()
	if err == nil {
		t.Fatal("Load succeeded, want an error")
	}
	for _, want := range []string{"DATABASE_URL", "APP_ENCRYPTION_KEY", "BCRYPT_COST"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("aggregated error is missing %s: %v", want, err)
		}
	}
}

func TestParseEncryptionKeyAcceptsEveryDocumentedEncoding(t *testing.T) {
	key := make([]byte, EncryptionKeySize)
	for i := range key {
		key[i] = byte(i)
	}

	encodings := map[string]string{
		"standard base64": base64.StdEncoding.EncodeToString(key),
		"raw base64":      base64.RawStdEncoding.EncodeToString(key),
		"url base64":      base64.URLEncoding.EncodeToString(key),
		"raw url base64":  base64.RawURLEncoding.EncodeToString(key),
		"hex":             hex.EncodeToString(key),
		"with whitespace": "  " + base64.StdEncoding.EncodeToString(key) + "\n",
	}

	for name, encoded := range encodings {
		t.Run(name, func(t *testing.T) {
			got, err := parseEncryptionKey(encoded)
			if err != nil {
				t.Fatalf("parseEncryptionKey: %v", err)
			}
			if string(got) != string(key) {
				t.Error("decoded key does not match the original")
			}
		})
	}
}

func TestParseEncryptionKeyRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"empty":             "",
		"whitespace only":   "   ",
		"too short":         base64.StdEncoding.EncodeToString(make([]byte, 16)),
		"too long":          base64.StdEncoding.EncodeToString(make([]byte, 64)),
		"not base64 or hex": "this is definitely not a key!!",
		"odd-length hex":    strings.Repeat("a", 63),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseEncryptionKey(input); err == nil {
				t.Errorf("parseEncryptionKey(%q) succeeded, want an error", input)
			}
		})
	}
}

func TestParseEncryptionKeyErrorIsActionable(t *testing.T) {
	// This message is the only guidance a first-time operator gets, so it must
	// name the command that produces a valid key.
	_, err := parseEncryptionKey("")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "genkey") {
		t.Errorf("error should point at `cli-login genkey`, got: %v", err)
	}
}

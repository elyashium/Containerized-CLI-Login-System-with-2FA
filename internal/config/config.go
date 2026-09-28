// Package config loads and validates runtime configuration from environment
// variables.
//
// Every value the brief calls "configurable" (session timeout, lockout
// threshold and duration) lives here, so behaviour can be tuned through
// docker-compose or a .env file without recompiling.
package config

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// EncryptionKeySize is the AES-256 key length required for TOTP secret storage.
const EncryptionKeySize = 32

// Config is the fully-validated runtime configuration.
type Config struct {
	// DatabaseURL is a libpq-style connection string.
	DatabaseURL string
	// DBConnectTimeout bounds the initial connection attempt, which may need to
	// wait for the database container to finish starting.
	DBConnectTimeout time.Duration

	// BcryptCost is the bcrypt work factor. Higher is slower and safer.
	BcryptCost int

	// MaxFailedAttempts is the number of consecutive failed authentication
	// steps tolerated before the account is locked.
	MaxFailedAttempts int
	// LockoutDuration is how long an account stays locked.
	LockoutDuration time.Duration

	// SessionIdleTimeout is the sliding inactivity window.
	SessionIdleTimeout time.Duration
	// SessionAbsoluteTimeout caps total session lifetime regardless of activity.
	SessionAbsoluteTimeout time.Duration
	// SessionPersist controls whether the session token is cached on disk so a
	// session survives restarting the CLI process.
	SessionPersist bool
	// StateDir holds the session token cache and the readline history file.
	StateDir string

	// TOTPIssuer is the label shown in the authenticator app.
	TOTPIssuer string
	// TOTPSkew is how many 30-second steps either side of now are accepted.
	TOTPSkew uint
	// PendingLoginTTL bounds how long a half-finished login (password accepted,
	// TOTP outstanding) stays valid.
	PendingLoginTTL time.Duration

	// EncryptionKey is the AES-256 key protecting TOTP secrets at rest.
	EncryptionKey []byte

	// MinPasswordLength is the shortest password accepted at registration.
	MinPasswordLength int
}

// Load reads configuration from the environment, applies defaults and
// validates the result. It returns a single aggregated error describing every
// problem found, so a misconfigured deployment can be fixed in one pass.
func Load() (*Config, error) {
	cfg := &Config{}
	var problems []string

	note := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	cfg.DatabaseURL = envString("DATABASE_URL", "")
	if cfg.DatabaseURL == "" {
		note("DATABASE_URL is required (example: postgres://app:secret@db:5432/clilogin?sslmode=disable)")
	}

	var err error

	if cfg.DBConnectTimeout, err = envDuration("DB_CONNECT_TIMEOUT", 30*time.Second); err != nil {
		note("%v", err)
	}
	if cfg.BcryptCost, err = envInt("BCRYPT_COST", 12); err != nil {
		note("%v", err)
	}
	if cfg.MaxFailedAttempts, err = envInt("MAX_FAILED_ATTEMPTS", 5); err != nil {
		note("%v", err)
	}
	if cfg.LockoutDuration, err = envDuration("LOCKOUT_DURATION", 15*time.Minute); err != nil {
		note("%v", err)
	}
	if cfg.SessionIdleTimeout, err = envDuration("SESSION_IDLE_TIMEOUT", 15*time.Minute); err != nil {
		note("%v", err)
	}
	if cfg.SessionAbsoluteTimeout, err = envDuration("SESSION_ABSOLUTE_TIMEOUT", 12*time.Hour); err != nil {
		note("%v", err)
	}
	if cfg.SessionPersist, err = envBool("SESSION_PERSIST", true); err != nil {
		note("%v", err)
	}
	if cfg.PendingLoginTTL, err = envDuration("PENDING_LOGIN_TTL", 2*time.Minute); err != nil {
		note("%v", err)
	}
	if cfg.MinPasswordLength, err = envInt("MIN_PASSWORD_LENGTH", 10); err != nil {
		note("%v", err)
	}

	skew, err := envInt("TOTP_SKEW", 1)
	if err != nil {
		note("%v", err)
	}
	if skew < 0 || skew > 10 {
		note("TOTP_SKEW must be between 0 and 10, got %d", skew)
		skew = 1
	}
	cfg.TOTPSkew = uint(skew)

	cfg.StateDir = envString("STATE_DIR", defaultStateDir())
	cfg.TOTPIssuer = envString("TOTP_ISSUER", "CLI Login")

	cfg.EncryptionKey, err = parseEncryptionKey(os.Getenv("APP_ENCRYPTION_KEY"))
	if err != nil {
		note("APP_ENCRYPTION_KEY: %v", err)
	}

	// Cross-field validation.
	if cfg.BcryptCost < 10 || cfg.BcryptCost > 31 {
		note("BCRYPT_COST must be between 10 and 31 (got %d); 12 is a good default", cfg.BcryptCost)
	}
	if cfg.MaxFailedAttempts < 1 {
		note("MAX_FAILED_ATTEMPTS must be at least 1 (got %d)", cfg.MaxFailedAttempts)
	}
	if cfg.LockoutDuration <= 0 {
		note("LOCKOUT_DURATION must be positive (got %s)", cfg.LockoutDuration)
	}
	if cfg.SessionIdleTimeout <= 0 {
		note("SESSION_IDLE_TIMEOUT must be positive (got %s)", cfg.SessionIdleTimeout)
	}
	if cfg.SessionAbsoluteTimeout <= 0 {
		note("SESSION_ABSOLUTE_TIMEOUT must be positive (got %s)", cfg.SessionAbsoluteTimeout)
	}
	if cfg.SessionIdleTimeout > cfg.SessionAbsoluteTimeout {
		note("SESSION_IDLE_TIMEOUT (%s) must not exceed SESSION_ABSOLUTE_TIMEOUT (%s)",
			cfg.SessionIdleTimeout, cfg.SessionAbsoluteTimeout)
	}
	if cfg.MinPasswordLength < 8 {
		note("MIN_PASSWORD_LENGTH must be at least 8 (got %d)", cfg.MinPasswordLength)
	}

	if len(problems) > 0 {
		return nil, fmt.Errorf("invalid configuration:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return cfg, nil
}

// parseEncryptionKey accepts a 32-byte key encoded as base64 (standard or raw)
// or as 64 hex characters.
func parseEncryptionKey(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("required; generate one with `cli-login genkey` (or `make genkey`)")
	}

	decoders := []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
		hex.DecodeString,
	}
	for _, decode := range decoders {
		if key, err := decode(raw); err == nil && len(key) == EncryptionKeySize {
			return key, nil
		}
	}
	return nil, fmt.Errorf("must decode to exactly %d bytes from base64 or hex", EncryptionKeySize)
}

// defaultStateDir picks a writable location for the session cache and history.
func defaultStateDir() string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return home + string(os.PathSeparator) + ".cli-login"
	}
	return ".cli-login"
}

func envString(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return fallback
}

func envInt(key string, fallback int) (int, error) {
	raw, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return fallback, fmt.Errorf("%s must be an integer, got %q", key, raw)
	}
	return v, nil
}

func envBool(key string, fallback bool) (bool, error) {
	raw, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	v, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return fallback, fmt.Errorf("%s must be a boolean (true/false), got %q", key, raw)
	}
	return v, nil
}

func envDuration(key string, fallback time.Duration) (time.Duration, error) {
	raw, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	v, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		return fallback, fmt.Errorf("%s must be a duration such as 15m or 12h, got %q", key, raw)
	}
	return v, nil
}

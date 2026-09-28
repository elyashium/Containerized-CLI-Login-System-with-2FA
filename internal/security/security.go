// Package security holds the cryptographic primitives used across the app:
// password hashing, random token generation, constant-time digests and
// authenticated encryption for TOTP secrets at rest.
package security

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// bcrypt silently truncates input beyond 72 bytes, which would make two long
// passwords sharing a prefix equivalent. We reject them instead.
const maxPasswordBytes = 72

// ErrPasswordTooLong is returned when a password exceeds bcrypt's input limit.
var ErrPasswordTooLong = fmt.Errorf("password must be at most %d bytes", maxPasswordBytes)

// HashPassword returns a bcrypt hash of password at the given cost.
func HashPassword(password string, cost int) (string, error) {
	if len(password) > maxPasswordBytes {
		return "", ErrPasswordTooLong
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(hash), nil
}

// VerifyPassword reports whether password matches hash. bcrypt's comparison is
// constant-time with respect to the hash contents.
func VerifyPassword(hash, password string) bool {
	if len(password) > maxPasswordBytes {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// DummyPasswordHash is a valid bcrypt hash of a random value, used to spend
// roughly the same CPU time when a username does not exist as when it does.
// Without this, an attacker can enumerate valid usernames by timing.
var DummyPasswordHash = "$2a$12$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

// WasteTimeComparing performs a throwaway bcrypt comparison so the unknown-user
// path costs about as much as the known-user path.
func WasteTimeComparing(password string) {
	_ = bcrypt.CompareHashAndPassword([]byte(DummyPasswordHash), []byte(password))
}

// NewSessionToken returns a 256-bit random token, URL-safe base64 encoded.
func NewSessionToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate session token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// HashToken returns the SHA-256 digest of a token. Session tokens are high
// entropy random values, so a fast digest is appropriate here — unlike
// passwords, they are not guessable and need no key stretching.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// ConstantTimeEqual compares two digests without leaking length or content
// through timing.
func ConstantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// recoveryCodeAlphabet excludes characters that are easy to misread when a
// user copies a code off the screen (0/O, 1/I/L, etc.).
const recoveryCodeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// NewRecoveryCode returns a human-transcribable single-use code of the form
// "XXXXX-XXXXX". The alphabet has 31 symbols, so 10 characters is ~49 bits of
// entropy — ample for a code that is also rate-limited by account lockout.
func NewRecoveryCode() (string, error) {
	const groupLen = 5
	var sb strings.Builder
	for group := 0; group < 2; group++ {
		if group > 0 {
			sb.WriteByte('-')
		}
		for i := 0; i < groupLen; i++ {
			idx, err := randomIndex(len(recoveryCodeAlphabet))
			if err != nil {
				return "", err
			}
			sb.WriteByte(recoveryCodeAlphabet[idx])
		}
	}
	return sb.String(), nil
}

// NormalizeRecoveryCode makes user input comparable to a stored code by
// upper-casing and stripping spaces and dashes.
func NormalizeRecoveryCode(code string) string {
	var sb strings.Builder
	for _, r := range strings.ToUpper(strings.TrimSpace(code)) {
		if r == '-' || r == ' ' {
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// HashRecoveryCode digests a normalized recovery code for storage.
func HashRecoveryCode(code string) []byte {
	sum := sha256.Sum256([]byte(NormalizeRecoveryCode(code)))
	return sum[:]
}

// randomIndex returns a uniformly random int in [0, n) using rejection
// sampling, avoiding the modulo bias of rand.Read()%n.
func randomIndex(n int) (int, error) {
	if n <= 0 {
		return 0, errors.New("randomIndex: n must be positive")
	}
	max := 256 - (256 % n) // largest multiple of n that fits in a byte
	buf := make([]byte, 1)
	for {
		if _, err := rand.Read(buf); err != nil {
			return 0, fmt.Errorf("read random byte: %w", err)
		}
		if int(buf[0]) < max {
			return int(buf[0]) % n, nil
		}
	}
}

// NewTOTPSecret returns a 160-bit base32 secret, the size recommended by
// RFC 4226 for HMAC-SHA1 based OTP.
func NewTOTPSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate TOTP secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

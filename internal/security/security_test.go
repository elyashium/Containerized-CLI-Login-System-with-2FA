package security

import (
	"strings"
	"testing"
)

func TestHashAndVerifyPassword(t *testing.T) {
	// Cost 4 is bcrypt's minimum; tests should not spend 250ms per hash.
	const cost = 4
	const password = "correct horse battery staple"

	hash, err := HashPassword(password, cost)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == password {
		t.Fatal("password was stored in plaintext")
	}
	if !strings.HasPrefix(hash, "$2") {
		t.Fatalf("expected a bcrypt hash, got %q", hash)
	}
	if !VerifyPassword(hash, password) {
		t.Error("correct password was rejected")
	}
	if VerifyPassword(hash, password+"x") {
		t.Error("incorrect password was accepted")
	}
	if VerifyPassword(hash, "") {
		t.Error("empty password was accepted")
	}
}

func TestHashPasswordUsesUniqueSalt(t *testing.T) {
	a, err := HashPassword("same-password-twice", 4)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	b, err := HashPassword("same-password-twice", 4)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if a == b {
		t.Error("identical passwords produced identical hashes: salt is not random")
	}
}

func TestHashPasswordRejectsOverlongInput(t *testing.T) {
	// bcrypt truncates at 72 bytes. Silently accepting longer input would make
	// two passwords sharing a 72-byte prefix interchangeable.
	long := strings.Repeat("a", 73)
	if _, err := HashPassword(long, 4); err == nil {
		t.Error("expected an error for a 73-byte password")
	}
	hash, err := HashPassword(strings.Repeat("a", 72), 4)
	if err != nil {
		t.Fatalf("72 bytes should be accepted: %v", err)
	}
	if VerifyPassword(hash, long) {
		t.Error("an over-long password must not verify against a truncated hash")
	}
}

func TestVerifyPasswordRejectsGarbageHash(t *testing.T) {
	if VerifyPassword("not-a-bcrypt-hash", "anything") {
		t.Error("a malformed hash must never verify")
	}
}

func TestWasteTimeComparingUsesAValidHash(t *testing.T) {
	// If DummyPasswordHash were malformed, bcrypt would return early and the
	// unknown-user path would be measurably faster than the known-user path.
	if !strings.HasPrefix(DummyPasswordHash, "$2") {
		t.Fatalf("dummy hash is not a bcrypt hash: %q", DummyPasswordHash)
	}
	WasteTimeComparing("whatever") // must not panic
}

func TestNewSessionTokenIsUniqueAndHighEntropy(t *testing.T) {
	seen := make(map[string]bool, 100)
	for i := 0; i < 100; i++ {
		token, err := NewSessionToken()
		if err != nil {
			t.Fatalf("NewSessionToken: %v", err)
		}
		// 32 random bytes, raw-url base64 => 43 characters.
		if len(token) != 43 {
			t.Fatalf("expected a 43-character token, got %d: %q", len(token), token)
		}
		if seen[token] {
			t.Fatal("NewSessionToken returned a duplicate")
		}
		seen[token] = true
	}
}

func TestHashTokenIsStableAndDistinct(t *testing.T) {
	a := HashToken("token-a")
	again := HashToken("token-a")
	b := HashToken("token-b")

	if len(a) != 32 {
		t.Fatalf("expected a 32-byte SHA-256 digest, got %d", len(a))
	}
	if !ConstantTimeEqual(a, again) {
		t.Error("hashing the same token twice produced different digests")
	}
	if ConstantTimeEqual(a, b) {
		t.Error("different tokens produced the same digest")
	}
}

func TestConstantTimeEqual(t *testing.T) {
	if !ConstantTimeEqual([]byte{1, 2, 3}, []byte{1, 2, 3}) {
		t.Error("equal slices reported unequal")
	}
	if ConstantTimeEqual([]byte{1, 2, 3}, []byte{1, 2, 4}) {
		t.Error("unequal slices reported equal")
	}
	if ConstantTimeEqual([]byte{1, 2, 3}, []byte{1, 2}) {
		t.Error("different lengths reported equal")
	}
}

func TestNewRecoveryCodeFormat(t *testing.T) {
	seen := make(map[string]bool, 50)
	for i := 0; i < 50; i++ {
		code, err := NewRecoveryCode()
		if err != nil {
			t.Fatalf("NewRecoveryCode: %v", err)
		}
		if len(code) != 11 || code[5] != '-' {
			t.Fatalf("expected the form XXXXX-XXXXX, got %q", code)
		}
		for _, r := range code {
			if r == '-' {
				continue
			}
			if !strings.ContainsRune(recoveryCodeAlphabet, r) {
				t.Fatalf("code %q contains %q, which is outside the alphabet", code, r)
			}
		}
		if seen[code] {
			t.Fatal("NewRecoveryCode returned a duplicate")
		}
		seen[code] = true
	}
}

func TestRecoveryCodeAlphabetExcludesAmbiguousCharacters(t *testing.T) {
	// A user reads these off a screen and types them back; 0/O and 1/I/L are
	// the classic transcription failures.
	for _, r := range "01OIL" {
		if strings.ContainsRune(recoveryCodeAlphabet, r) {
			t.Errorf("alphabet should not contain the ambiguous character %q", r)
		}
	}
}

func TestNormalizeRecoveryCode(t *testing.T) {
	cases := []struct{ in, want string }{
		{"ABCDE-FGHJK", "ABCDEFGHJK"},
		{"abcde-fghjk", "ABCDEFGHJK"},
		{"  ABCDE FGHJK  ", "ABCDEFGHJK"},
		{"ABCDEFGHJK", "ABCDEFGHJK"},
		{"a-b c-d", "ABCD"},
	}
	for _, tc := range cases {
		if got := NormalizeRecoveryCode(tc.in); got != tc.want {
			t.Errorf("NormalizeRecoveryCode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestHashRecoveryCodeIgnoresFormatting(t *testing.T) {
	// Whether the user types the dash or not must not change the lookup.
	withDash := HashRecoveryCode("ABCDE-FGHJK")
	withoutDash := HashRecoveryCode("abcdefghjk")
	if !ConstantTimeEqual(withDash, withoutDash) {
		t.Error("formatting differences changed the recovery code digest")
	}
	other := HashRecoveryCode("ABCDE-FGHJM")
	if ConstantTimeEqual(withDash, other) {
		t.Error("different codes produced the same digest")
	}
}

func TestRandomIndexStaysInRange(t *testing.T) {
	const n = 31
	counts := make([]int, n)
	for i := 0; i < 3100; i++ {
		idx, err := randomIndex(n)
		if err != nil {
			t.Fatalf("randomIndex: %v", err)
		}
		if idx < 0 || idx >= n {
			t.Fatalf("randomIndex returned %d, outside [0,%d)", idx, n)
		}
		counts[idx]++
	}
	// Rejection sampling should give a roughly flat distribution. With 100
	// expected per bucket this bound is loose enough never to flake but tight
	// enough to catch a value that is never produced.
	for i, c := range counts {
		if c == 0 {
			t.Errorf("value %d was never produced in 3100 draws", i)
		}
	}
	if _, err := randomIndex(0); err == nil {
		t.Error("randomIndex(0) should fail rather than divide by zero")
	}
}

func TestNewTOTPSecret(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatalf("NewTOTPSecret: %v", err)
	}
	// 20 bytes base32-encoded without padding is 32 characters.
	if len(secret) != 32 {
		t.Fatalf("expected a 32-character base32 secret, got %d: %q", len(secret), secret)
	}
	for _, r := range secret {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", r) {
			t.Fatalf("secret %q contains non-base32 character %q", secret, r)
		}
	}
}

package security

import (
	"bytes"
	"errors"
	"testing"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("expected a 32-byte key, got %d", len(key))
	}
	return key
}

func newTestCipher(t *testing.T) *Cipher {
	t.Helper()
	c, err := NewCipher(testKey(t))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	return c
}

func TestCipherRoundTrip(t *testing.T) {
	c := newTestCipher(t)
	aad := UserAAD(42)

	const secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	sealed, err := c.EncryptString(secret, aad)
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	if bytes.Contains(sealed, []byte(secret)) {
		t.Fatal("the plaintext secret is visible in the ciphertext")
	}

	got, err := c.DecryptString(sealed, aad)
	if err != nil {
		t.Fatalf("DecryptString: %v", err)
	}
	if got != secret {
		t.Fatalf("round trip changed the value: got %q, want %q", got, secret)
	}
}

func TestCipherProducesDistinctCiphertexts(t *testing.T) {
	c := newTestCipher(t)
	aad := UserAAD(1)

	// A fresh nonce per message means an observer cannot tell that two users
	// happen to share a secret.
	a, err := c.EncryptString("same-secret", aad)
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	b, err := c.EncryptString("same-secret", aad)
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Error("encrypting the same plaintext twice produced identical ciphertext: the nonce is being reused")
	}
}

func TestCipherRejectsTamperedCiphertext(t *testing.T) {
	c := newTestCipher(t)
	aad := UserAAD(7)

	sealed, err := c.EncryptString("secret-value", aad)
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}

	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"flip a ciphertext bit", func(b []byte) []byte {
			out := bytes.Clone(b)
			out[len(out)-5] ^= 0x01
			return out
		}},
		{"flip a nonce bit", func(b []byte) []byte {
			out := bytes.Clone(b)
			out[0] ^= 0x01
			return out
		}},
		{"truncate the tag", func(b []byte) []byte {
			return bytes.Clone(b[:len(b)-1])
		}},
		{"shorter than the nonce", func(b []byte) []byte {
			return bytes.Clone(b[:4])
		}},
		{"empty", func([]byte) []byte { return nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := c.Decrypt(tc.mutate(sealed), aad); !errors.Is(err, ErrDecryptFailed) {
				t.Errorf("expected ErrDecryptFailed, got %v", err)
			}
		})
	}
}

func TestCipherRejectsWrongKey(t *testing.T) {
	encrypter := newTestCipher(t)
	decrypter := newTestCipher(t)
	aad := UserAAD(3)

	sealed, err := encrypter.EncryptString("secret-value", aad)
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	if _, err := decrypter.DecryptString(sealed, aad); !errors.Is(err, ErrDecryptFailed) {
		t.Errorf("a different key must not decrypt; got %v", err)
	}
}

// TestCipherBindsSecretsToTheirOwner is the point of the AAD: an attacker who
// can write to the database must not be able to move one user's sealed TOTP
// secret into another user's row and then authenticate as them.
func TestCipherBindsSecretsToTheirOwner(t *testing.T) {
	c := newTestCipher(t)

	const secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	sealed, err := c.EncryptString(secret, UserAAD(1))
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}

	if _, err := c.DecryptString(sealed, UserAAD(2)); !errors.Is(err, ErrDecryptFailed) {
		t.Errorf("another user's AAD must not open the secret; got %v", err)
	}
	// Nor does dropping the binding altogether.
	if _, err := c.DecryptString(sealed, nil); !errors.Is(err, ErrDecryptFailed) {
		t.Errorf("omitting the AAD must not open the secret; got %v", err)
	}

	// The rightful owner still gets it back.
	got, err := c.DecryptString(sealed, UserAAD(1))
	if err != nil {
		t.Fatalf("the owning user should be able to decrypt: %v", err)
	}
	if got != secret {
		t.Errorf("round trip changed the value: got %q, want %q", got, secret)
	}
}

func TestUserAADIsDistinctPerUser(t *testing.T) {
	// Two accounts must never derive the same binding, and it must be stable
	// across calls or a stored secret would stop opening.
	seen := map[string]int64{}
	for _, id := range []int64{0, 1, 2, 10, 11, 100, 1 << 40} {
		aad := string(UserAAD(id))
		if prev, dup := seen[aad]; dup {
			t.Errorf("users %d and %d derive the same AAD %q", prev, id, aad)
		}
		seen[aad] = id

		if again := string(UserAAD(id)); again != aad {
			t.Errorf("UserAAD(%d) is not stable: %q then %q", id, aad, again)
		}
	}
}

func TestNewCipherRejectsBadKeySizes(t *testing.T) {
	for _, size := range []int{0, 1, 16, 24, 31, 33, 64} {
		if _, err := NewCipher(make([]byte, size)); !errors.Is(err, ErrInvalidKeySize) {
			t.Errorf("NewCipher with a %d-byte key: expected ErrInvalidKeySize, got %v", size, err)
		}
	}
}

func TestGenerateKeyIsRandom(t *testing.T) {
	seen := make(map[string]bool, 20)
	for i := 0; i < 20; i++ {
		key := testKey(t)
		if seen[string(key)] {
			t.Fatal("GenerateKey returned a duplicate")
		}
		seen[string(key)] = true
	}
}

func TestCipherHandlesEmptyPlaintext(t *testing.T) {
	c := newTestCipher(t)

	sealed, err := c.Encrypt(nil, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := c.Decrypt(sealed, nil)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty plaintext, got %q", got)
	}
}

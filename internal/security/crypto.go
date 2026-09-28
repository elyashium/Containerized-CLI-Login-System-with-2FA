package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// ErrInvalidKeySize is returned when a key is not 32 bytes (AES-256).
var ErrInvalidKeySize = errors.New("encryption key must be 32 bytes")

// ErrDecryptFailed is returned when ciphertext fails authentication. It is
// deliberately vague: distinguishing "wrong key" from "tampered data" would
// leak information to an attacker who can submit ciphertexts.
var ErrDecryptFailed = errors.New("decrypt: ciphertext is corrupt or the encryption key is wrong")

// Cipher provides authenticated encryption for secrets held at rest.
//
// TOTP secrets are stored encrypted rather than plain because a read-only
// database leak would otherwise let an attacker mint valid 2FA codes for every
// user, silently defeating the second factor. The key lives in the app's
// environment, not the database, so one leak is not enough.
type Cipher struct {
	aead cipher.AEAD
}

// NewCipher builds an AES-256-GCM cipher from a 32-byte key.
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("%w, got %d", ErrInvalidKeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// Encrypt seals plaintext, returning nonce || ciphertext || tag.
//
// aad is authenticated but not encrypted. Callers pass a value identifying
// where the ciphertext is allowed to live — for TOTP secrets, the owning user
// ID — which binds the sealed value to that row. An attacker who can write to
// the database then cannot copy one user's secret into another user's row to
// authenticate as them: the tag no longer verifies. Pass nil when there is
// nothing meaningful to bind to.
func (c *Cipher) Encrypt(plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	// Seal appends to its first argument, so passing nonce puts the nonce in
	// front of the ciphertext in a single allocation.
	return c.aead.Seal(nonce, nonce, plaintext, aad), nil
}

// Decrypt opens a value produced by Encrypt. aad must match exactly what was
// supplied when sealing, or authentication fails.
func (c *Cipher) Decrypt(sealed, aad []byte) ([]byte, error) {
	nonceSize := c.aead.NonceSize()
	if len(sealed) < nonceSize {
		return nil, ErrDecryptFailed
	}
	nonce, ciphertext := sealed[:nonceSize], sealed[nonceSize:]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	return plaintext, nil
}

// EncryptString is a convenience wrapper for string secrets.
func (c *Cipher) EncryptString(s string, aad []byte) ([]byte, error) {
	return c.Encrypt([]byte(s), aad)
}

// DecryptString is a convenience wrapper for string secrets.
func (c *Cipher) DecryptString(sealed, aad []byte) (string, error) {
	plaintext, err := c.Decrypt(sealed, aad)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// UserAAD returns the additional authenticated data that binds a sealed secret
// to one account. Sealing and opening must derive it identically, so it lives
// here rather than being spelled out at each call site.
func UserAAD(userID int64) []byte {
	return []byte("cli-login/mfa-secret/user/" + strconv.FormatInt(userID, 10))
}

// GenerateKey returns a fresh 32-byte AES-256 key, used by the `genkey`
// command to help operators produce a valid APP_ENCRYPTION_KEY.
func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return key, nil
}

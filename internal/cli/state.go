package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// storedSession is the on-disk session cache.
//
// Persisting the token lets a session survive restarting the CLI, which is
// what makes a configurable session timeout observable: quit, come back
// within the window and you are still signed in; come back later and you are
// not. The file holds the bearer token, so it is written 0600 inside a 0700
// directory, and the authoritative expiry check always happens server-side —
// a tampered file cannot extend a session.
type storedSession struct {
	Token     string    `json:"token"`
	Username  string    `json:"username"`
	ExpiresAt time.Time `json:"expires_at"`
	SavedAt   time.Time `json:"saved_at"`
}

// sessionStatePath returns the location of the session cache.
func sessionStatePath(stateDir string) string {
	return filepath.Join(stateDir, "session.json")
}

// ensureStateDir creates the state directory with owner-only permissions.
func ensureStateDir(stateDir string) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("create state directory %s: %w", stateDir, err)
	}
	return nil
}

// saveSession writes the token cache atomically.
//
// Writing to a temporary file and renaming avoids leaving a truncated or
// half-written token behind if the process dies mid-write.
func saveSession(stateDir string, s storedSession) error {
	if err := ensureStateDir(stateDir); err != nil {
		return err
	}
	s.SavedAt = time.Now()

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encode session: %w", err)
	}

	path := sessionStatePath(stateDir)
	tmp, err := os.CreateTemp(stateDir, "session-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp session file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		// Best-effort cleanup if we failed before the rename.
		if _, statErr := os.Stat(tmpName); statErr == nil {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil && !errors.Is(err, fs.ErrPermission) {
		// Chmod is a no-op on Windows; only treat real failures as fatal.
		tmp.Close()
		return fmt.Errorf("secure session file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write session file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close session file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("install session file: %w", err)
	}
	return nil
}

// loadSession reads the cached session, returning ok=false when absent or
// unreadable. A corrupt cache is never fatal: the user simply logs in again.
func loadSession(stateDir string) (storedSession, bool) {
	data, err := os.ReadFile(sessionStatePath(stateDir))
	if err != nil {
		return storedSession{}, false
	}
	var s storedSession
	if err := json.Unmarshal(data, &s); err != nil || s.Token == "" {
		return storedSession{}, false
	}
	return s, true
}

// clearSession removes the cached session.
func clearSession(stateDir string) error {
	err := os.Remove(sessionStatePath(stateDir))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("clear session file: %w", err)
	}
	return nil
}

// historyPath returns the readline history file location.
func historyPath(stateDir string) string {
	return filepath.Join(stateDir, "history")
}

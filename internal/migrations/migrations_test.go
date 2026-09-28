package migrations

import (
	"sort"
	"strings"
	"testing"
)

func TestLoadEmbeddedMigrations(t *testing.T) {
	all, err := load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(all) == 0 {
		t.Fatal("no migrations were embedded; check the //go:embed directive")
	}

	for _, m := range all {
		if m.version <= 0 {
			t.Errorf("migration %q has a non-positive version %d", m.name, m.version)
		}
		if strings.TrimSpace(m.sql) == "" {
			t.Errorf("migration %q is empty", m.name)
		}
		if !strings.HasSuffix(m.name, ".sql") {
			t.Errorf("migration %q should be a .sql file", m.name)
		}
	}
}

func TestLoadReturnsMigrationsInVersionOrder(t *testing.T) {
	all, err := load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !sort.SliceIsSorted(all, func(i, j int) bool { return all[i].version < all[j].version }) {
		t.Error("migrations are not sorted by version")
	}
	// Duplicate versions would make "applied" bookkeeping ambiguous; load()
	// rejects them, so reaching here means they are unique.
	seen := map[int]string{}
	for _, m := range all {
		if prev, dup := seen[m.version]; dup {
			t.Errorf("version %d is used by both %s and %s", m.version, prev, m.name)
		}
		seen[m.version] = m.name
	}
}

func TestInitialMigrationDefinesTheExpectedSchema(t *testing.T) {
	all, err := load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	var combined strings.Builder
	for _, m := range all {
		combined.WriteString(strings.ToLower(m.sql))
	}
	schema := combined.String()

	// The brief requires the schema to be part of the deliverable, so assert
	// the tables the application actually depends on are present.
	for _, table := range []string{"users", "sessions", "mfa_recovery_codes", "auth_events"} {
		if !strings.Contains(schema, "create table if not exists "+table) {
			t.Errorf("migrations do not create the %q table", table)
		}
	}

	// Columns the store reads by name. A rename without a matching migration
	// would otherwise only fail at runtime against a live database.
	for _, column := range []string{
		"password_hash", "username_lower", "failed_attempts", "locked_until",
		"mfa_enabled", "mfa_secret", "mfa_last_timestep", "last_login_at",
		"token_hash", "idle_expires_at", "absolute_expires_at", "revoked_at",
	} {
		if !strings.Contains(schema, column) {
			t.Errorf("migrations do not mention the %q column", column)
		}
	}

	// Case-insensitive uniqueness is what stops "Alice" and "alice" being two
	// different accounts.
	if !strings.Contains(schema, "username_lower") || !strings.Contains(schema, "unique") {
		t.Error("the schema should enforce unique usernames case-insensitively")
	}
}

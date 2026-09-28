// Package migrations applies embedded SQL migrations at startup.
//
// The files are embedded in the binary, so the container image needs no
// separate migration tool or mounted SQL directory — running the app is
// enough to bring an empty database up to date.
package migrations

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed sql/*.sql
var files embed.FS

// migration is one versioned SQL file.
type migration struct {
	version int
	name    string
	sql     string
}

// Apply runs every migration that has not yet been recorded as applied.
//
// A Postgres advisory lock serialises concurrent runners: with several app
// containers starting at once, exactly one applies a given migration while the
// others wait and then find there is nothing to do.
func Apply(ctx context.Context, pool *pgxpool.Pool) (applied []string, err error) {
	const advisoryLockKey = 8123407625510043 // arbitrary, app-specific

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire connection for migrations: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, advisoryLockKey); err != nil {
		return nil, fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		if _, unlockErr := conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, advisoryLockKey); unlockErr != nil && err == nil {
			err = fmt.Errorf("release migration lock: %w", unlockErr)
		}
	}()

	const createTable = `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version     INTEGER PRIMARY KEY,
			name        TEXT        NOT NULL,
			applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
		)`
	if _, err := conn.Exec(ctx, createTable); err != nil {
		return nil, fmt.Errorf("create schema_migrations: %w", err)
	}

	appliedVersions := map[int]bool{}
	rows, err := conn.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("read applied migrations: %w", err)
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan applied migration: %w", err)
		}
		appliedVersions[v] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate applied migrations: %w", err)
	}

	all, err := load()
	if err != nil {
		return nil, err
	}

	for _, m := range all {
		if appliedVersions[m.version] {
			continue
		}
		// Each migration runs in its own transaction: DDL is transactional in
		// Postgres, so a failure leaves no half-applied schema behind.
		tx, err := conn.Begin(ctx)
		if err != nil {
			return applied, fmt.Errorf("begin migration %s: %w", m.name, err)
		}
		if _, err := tx.Exec(ctx, m.sql); err != nil {
			_ = tx.Rollback(ctx)
			return applied, fmt.Errorf("apply migration %s: %w", m.name, err)
		}
		const record = `INSERT INTO schema_migrations (version, name) VALUES ($1, $2)`
		if _, err := tx.Exec(ctx, record, m.version, m.name); err != nil {
			_ = tx.Rollback(ctx)
			return applied, fmt.Errorf("record migration %s: %w", m.name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return applied, fmt.Errorf("commit migration %s: %w", m.name, err)
		}
		applied = append(applied, m.name)
	}
	return applied, nil
}

// load reads and sorts the embedded migration files. Names must start with a
// numeric version, e.g. "0001_init.sql".
func load() ([]migration, error) {
	entries, err := fs.ReadDir(files, "sql")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations: %w", err)
	}

	var out []migration
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		name := entry.Name()
		versionPart, _, found := strings.Cut(strings.TrimSuffix(name, ".sql"), "_")
		if !found {
			return nil, fmt.Errorf("migration %q must be named <version>_<description>.sql", name)
		}
		version, err := strconv.Atoi(versionPart)
		if err != nil {
			return nil, fmt.Errorf("migration %q has a non-numeric version prefix: %w", name, err)
		}
		body, err := files.ReadFile("sql/" + name)
		if err != nil {
			return nil, fmt.Errorf("read migration %q: %w", name, err)
		}
		out = append(out, migration{version: version, name: name, sql: string(body)})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })

	for i := 1; i < len(out); i++ {
		if out[i].version == out[i-1].version {
			return nil, fmt.Errorf("duplicate migration version %d (%s and %s)",
				out[i].version, out[i-1].name, out[i].name)
		}
	}
	return out, nil
}

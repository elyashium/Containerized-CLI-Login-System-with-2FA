// Command cli-login is a containerized interactive login shell with optional
// TOTP two-factor authentication.
//
// Usage:
//
//	cli-login              start the interactive shell
//	cli-login migrate      apply database migrations and exit
//	cli-login genkey       print a fresh APP_ENCRYPTION_KEY and exit
//	cli-login version      print the version and exit
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/elyashium/Containerized-CLI-Login-System-with-2FA/internal/auth"
	"github.com/elyashium/Containerized-CLI-Login-System-with-2FA/internal/cli"
	"github.com/elyashium/Containerized-CLI-Login-System-with-2FA/internal/config"
	"github.com/elyashium/Containerized-CLI-Login-System-with-2FA/internal/migrations"
	"github.com/elyashium/Containerized-CLI-Login-System-with-2FA/internal/security"
	"github.com/elyashium/Containerized-CLI-Login-System-with-2FA/internal/store"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		// Diagnostics go to stderr so they stay separate from the shell
		// transcript on stdout.
		fmt.Fprintf(os.Stderr, "\nerror: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	command := ""
	if len(args) > 0 {
		command = args[0]
	}

	// genkey, version and help must work before configuration is valid —
	// genkey exists precisely to produce the key that Load() demands.
	switch command {
	case "genkey":
		return genkey()
	case "version", "--version", "-v":
		fmt.Printf("cli-login %s\n", version)
		return nil
	case "help", "--help", "-h":
		usage(os.Stdout)
		return nil
	case "", "shell", "migrate":
		// Handled below, once configuration and the database are available.
	default:
		usage(os.Stderr)
		return fmt.Errorf("unknown command %q", command)
	}

	log := newLogger()

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// Cancel on SIGINT/SIGTERM so `docker compose down` and Ctrl-C at a
	// non-interactive prompt both shut down cleanly. While readline holds the
	// terminal in raw mode, Ctrl-C is delivered to it as input rather than as a
	// signal, so this does not interfere with cancelling a prompt.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	connectCtx, cancel := context.WithTimeout(ctx, cfg.DBConnectTimeout)
	defer cancel()

	st, err := store.New(connectCtx, cfg.DatabaseURL, cfg.DBConnectTimeout)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer st.Close()

	// Migrations run on every start. They are idempotent and guarded by a
	// Postgres advisory lock, so starting several containers at once is safe
	// and the CLI is usable immediately after `docker compose up`.
	migrateCtx, cancelMigrate := context.WithTimeout(ctx, 60*time.Second)
	defer cancelMigrate()
	applied, err := migrations.Apply(migrateCtx, st.Pool())
	if err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	if len(applied) > 0 {
		log.Info("applied database migrations", "migrations", applied)
	}

	if command == "migrate" {
		if len(applied) == 0 {
			fmt.Println("database schema already up to date")
		} else {
			fmt.Printf("applied %d migration(s): %v\n", len(applied), applied)
		}
		return nil
	}

	// Housekeeping: drop sessions that expired more than a day ago. Best
	// effort — a failure here must not stop anyone logging in.
	if removed, err := st.DeleteExpiredSessions(ctx, 24*time.Hour); err != nil {
		log.Warn("could not prune expired sessions", "error", err)
	} else if removed > 0 {
		log.Debug("pruned expired sessions", "count", removed)
	}

	authSvc, err := auth.NewService(st, cfg, log)
	if err != nil {
		return err
	}

	shell, err := cli.New(authSvc, cfg, log, version)
	if err != nil {
		return err
	}
	defer shell.Close()

	if err := shell.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// genkey prints a new AES-256 key for APP_ENCRYPTION_KEY, base64-encoded so it
// can be pasted straight into .env.
func genkey() error {
	key, err := security.GenerateKey()
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(key))
	return nil
}

// newLogger configures structured logging on stderr, leaving stdout for the
// shell transcript. LOG_LEVEL accepts debug, info, warn or error.
func newLogger() *slog.Logger {
	level := slog.LevelWarn // quiet by default: this is an interactive tool
	switch os.Getenv("LOG_LEVEL") {
	case "debug", "DEBUG":
		level = slog.LevelDebug
	case "info", "INFO":
		level = slog.LevelInfo
	case "warn", "WARN", "warning":
		level = slog.LevelWarn
	case "error", "ERROR":
		level = slog.LevelError
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

func usage(w *os.File) {
	fmt.Fprint(w, `cli-login — interactive login shell with optional TOTP 2FA

Usage:
  cli-login            start the interactive shell (default)
  cli-login migrate    apply database migrations and exit
  cli-login genkey     print a fresh APP_ENCRYPTION_KEY and exit
  cli-login version    print the version and exit

Configuration is read from the environment; see .env.example.
`)
}

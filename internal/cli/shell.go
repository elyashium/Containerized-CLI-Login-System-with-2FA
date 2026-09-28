// Package cli implements the interactive shell: the REPL, tab-completion,
// command dispatch and all user-facing rendering.
//
// It deliberately contains no security decisions — those live in the auth
// package — so this layer stays focused on input and presentation.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/elyashium/Containerized-CLI-Login-System-with-2FA/internal/auth"
	"github.com/elyashium/Containerized-CLI-Login-System-with-2FA/internal/config"
	"github.com/elyashium/Containerized-CLI-Login-System-with-2FA/internal/models"
)

// errExit unwinds the REPL when the user asks to quit.
var errExit = errors.New("exit")

// Shell is the interactive command loop.
type Shell struct {
	auth    *auth.Service
	cfg     *config.Config
	out     *Output
	log     *slog.Logger
	reader  lineReader
	version string

	// Session state for the signed-in user. All three are set and cleared
	// together by setSession/clearLocalSession.
	token   string
	session *models.Session
	user    *models.User
}

// New builds a Shell, choosing an interactive or piped input backend based on
// whether stdin is a terminal.
func New(authSvc *auth.Service, cfg *config.Config, log *slog.Logger, version string) (*Shell, error) {
	sh := &Shell{auth: authSvc, cfg: cfg, log: log, version: version}
	sh.out = NewOutput(os.Stdout)

	if stdinIsTerminal() {
		reader, err := newReadlineReader(cfg.StateDir, &commandCompleter{shell: sh})
		if err != nil {
			return nil, err
		}
		sh.reader = reader
		// Route output through readline's writer so redraws and ANSI
		// sequences behave correctly (notably on Windows terminals).
		sh.out.SetWriter(reader.Writer())
	} else {
		sh.reader = newPlainReader(os.Stdin, os.Stdout)
	}
	return sh, nil
}

// Close releases terminal resources.
func (s *Shell) Close() error { return s.reader.Close() }

// Run executes the read-eval-print loop until the user exits or stdin closes.
func (s *Shell) Run(ctx context.Context) error {
	s.printBanner()
	s.restoreSession(ctx)

	for {
		// Honour cancellation (SIGTERM) between commands.
		if err := ctx.Err(); err != nil {
			return nil
		}

		line, err := s.reader.ReadLine(s.prompt())
		switch {
		case errors.Is(err, ErrInterrupted):
			// Ctrl-C abandons the current line rather than the program;
			// this matches how a shell behaves and avoids losing a session
			// to a stray keystroke.
			if strings.TrimSpace(line) == "" {
				s.out.Hint("(use `exit` or Ctrl-D to quit)")
			}
			continue
		case errors.Is(err, io.EOF):
			s.out.Blank()
			s.out.Info("Goodbye.")
			return nil
		case err != nil:
			return fmt.Errorf("read input: %w", err)
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Only complete command lines enter history, so secrets typed at
		// sub-prompts are never written to disk.
		s.reader.SaveHistory(line)

		if err := s.dispatch(ctx, line); err != nil {
			if errors.Is(err, errExit) {
				return nil
			}
			if errors.Is(err, io.EOF) {
				s.out.Blank()
				return nil
			}
			// A command that failed is reported and the loop continues; only
			// unexpected internal errors reach here already formatted.
			s.out.Error("%v", err)
		}
	}
}

// dispatch parses a command line and runs the matching command.
func (s *Shell) dispatch(ctx context.Context, line string) error {
	fields := strings.Fields(line)
	name := strings.ToLower(fields[0])
	args := fields[1:]

	cmd, ok := s.lookup(name)
	if !ok {
		s.out.Error("Unknown command %q.", name)
		if suggestion := s.suggest(name); suggestion != "" {
			s.out.Hint("Did you mean `%s`?", suggestion)
		}
		s.out.Hint("Type `help` to see available commands.")
		return nil
	}

	// Enforce the two command sets from the brief: some commands only make
	// sense signed out, others only signed in.
	if cmd.requiresAuth && !s.isAuthenticated() {
		s.out.Error("`%s` requires you to be signed in.", cmd.name)
		s.out.Hint("Run `login` first.")
		return nil
	}
	if cmd.requiresGuest && s.isAuthenticated() {
		s.out.Error("`%s` is not available while signed in as %s.", cmd.name, s.user.Username)
		s.out.Hint("Run `logout` first.")
		return nil
	}

	// Revalidate the session before every authenticated command so an expired
	// session is caught at the moment it is used.
	if cmd.requiresAuth {
		if err := s.refreshSession(ctx); err != nil {
			return nil // refreshSession already reported the problem
		}
	}

	return cmd.run(ctx, s, args)
}

// suggest returns the closest known command name, for typo recovery.
func (s *Shell) suggest(input string) string {
	best, bestDist := "", 3 // only suggest within edit distance 2
	for _, cmd := range s.availableCommands() {
		for _, candidate := range append([]string{cmd.name}, cmd.aliases...) {
			if d := editDistance(input, candidate); d < bestDist {
				best, bestDist = cmd.name, d
			}
		}
	}
	return best
}

// editDistance computes Levenshtein distance between two short strings.
func editDistance(a, b string) int {
	ar, br := []rune(a), []rune(b)
	prev := make([]int, len(br)+1)
	curr := make([]int, len(br)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ar); i++ {
		curr[0] = i
		for j := 1; j <= len(br); j++ {
			cost := 1
			if ar[i-1] == br[j-1] {
				cost = 0
			}
			curr[j] = min3(curr[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[len(br)]
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}

// prompt renders the shell prompt, reflecting the current identity.
func (s *Shell) prompt() string {
	if s.isAuthenticated() {
		return fmt.Sprintf("%s@auth> ", s.user.Username)
	}
	return "auth> "
}

// isAuthenticated reports whether a session is currently held.
func (s *Shell) isAuthenticated() bool {
	return s.token != "" && s.user != nil && s.session != nil
}

// setSession records a newly established session and caches the token.
func (s *Shell) setSession(token string, session *models.Session, user *models.User) {
	s.token, s.session, s.user = token, session, user

	if !s.cfg.SessionPersist {
		return
	}
	err := saveSession(s.cfg.StateDir, storedSession{
		Token:     token,
		Username:  user.Username,
		ExpiresAt: session.ExpiresAt(),
	})
	if err != nil {
		// Not fatal: the in-memory session still works for this process.
		s.log.Warn("could not cache session", "error", err)
		s.out.Warn("Session could not be cached to disk: %v", err)
	}
}

// clearLocalSession drops local session state and the on-disk cache.
func (s *Shell) clearLocalSession() {
	s.token, s.session, s.user = "", nil, nil
	if err := clearSession(s.cfg.StateDir); err != nil {
		s.log.Warn("could not clear cached session", "error", err)
	}
}

// restoreSession resumes a cached session at startup if it is still valid.
func (s *Shell) restoreSession(ctx context.Context) {
	if !s.cfg.SessionPersist {
		return
	}
	cached, ok := loadSession(s.cfg.StateDir)
	if !ok {
		return
	}

	// The server decides validity; the cached expiry is only a hint.
	session, user, err := s.auth.ResolveSession(ctx, cached.Token)
	if err != nil {
		if errors.Is(err, auth.ErrSessionExpired) {
			s.out.Info("Your previous session for %s expired.", cached.Username)
		}
		_ = clearSession(s.cfg.StateDir)
		return
	}

	s.token, s.session, s.user = cached.Token, session, user
	s.out.Success("Resumed session for %s.", s.out.Bold(user.Username))
	s.out.Hint("Session expires %s. Run `whoami` for details.",
		session.ExpiresAt().Local().Format(timeLayout))
	s.out.Blank()
}

// refreshSession revalidates and extends the session before an authenticated
// command runs, reporting and clearing state if it is no longer valid.
func (s *Shell) refreshSession(ctx context.Context) error {
	session, user, err := s.auth.ResolveSession(ctx, s.token)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrSessionExpired):
			s.out.Error("Your session expired after %s of inactivity.",
				auth.FormatDuration(s.cfg.SessionIdleTimeout))
			s.out.Hint("Run `login` to sign in again.")
		case errors.Is(err, auth.ErrSessionInvalid):
			s.out.Error("Your session is no longer valid.")
			s.out.Hint("Run `login` to sign in again.")
		default:
			s.out.Error("Could not verify your session: %v", err)
		}
		s.clearLocalSession()
		return err
	}

	s.session, s.user = session, user

	// Keep the cached expiry in step with the slid deadline.
	if s.cfg.SessionPersist {
		_ = saveSession(s.cfg.StateDir, storedSession{
			Token:     s.token,
			Username:  user.Username,
			ExpiresAt: session.ExpiresAt(),
		})
	}
	return nil
}

// printBanner shows the welcome header.
func (s *Shell) printBanner() {
	s.out.Blank()
	s.out.Println(s.out.Bold("  Secure CLI Login") + s.out.Dim(" · "+s.version))
	s.out.Println(s.out.Dim("  Type `help` for commands, `exit` to quit."))
	s.out.Blank()
}

// printUserDetails renders the account/session summary shown after login and
// by `whoami`. This is the block required by the brief.
func (s *Shell) printUserDetails(ctx context.Context, session *models.Session, user *models.User, previousLogin *time.Time) {
	s.out.Heading("Account")
	s.out.Field("Username", s.out.Bold(user.Username))
	s.out.Field("Registered", formatTime(user.CreatedAt))

	if user.MFAEnabled {
		s.out.FieldC("Two-factor auth", ansiGreen, "enabled")
		if remaining, err := s.auth.RecoveryCodesRemaining(ctx, user.ID); err == nil {
			label := fmt.Sprintf("%d unused", remaining)
			if remaining == 0 {
				s.out.FieldC("Recovery codes", ansiYellow, "none left — re-run enable-2fa to reissue")
			} else {
				s.out.Field("Recovery codes", label)
			}
		}
	} else {
		s.out.FieldC("Two-factor auth", ansiYellow, "disabled")
	}

	// "Last login" means the login before this one; showing the current one
	// would just say "now" and tell the user nothing.
	s.out.Field("Last login", formatTimePtr(previousLogin, s.out.Dim("first login")))

	s.out.Heading("Session")
	s.out.Field("Started", formatTime(session.CreatedAt))
	s.out.Field("Expires", formatTime(session.ExpiresAt()))
	s.out.Field("Idle timeout", auth.FormatDuration(s.cfg.SessionIdleTimeout))
	s.out.Field("Hard expiry", formatTime(session.AbsoluteExpiresAt))
	s.out.Blank()
}

// ------------------------------------------------------------- completion

// commandCompleter offers tab-completion for the commands currently
// available, so the suggestions always match what the user can actually run.
type commandCompleter struct {
	shell *Shell
}

// Do implements readline.AutoCompleter. It returns the remainder of each
// matching candidate plus the length of the prefix being completed, which is
// the contract readline's own PrefixCompleter follows.
func (c *commandCompleter) Do(line []rune, pos int) ([][]rune, int) {
	text := string(line[:pos])
	trimmed := strings.TrimLeft(text, " ")

	// Completing an argument rather than the command itself.
	if strings.Contains(trimmed, " ") {
		fields := strings.Fields(trimmed)
		// `help <command>` is the only command taking a completable argument.
		if len(fields) >= 1 && fields[0] == "help" {
			prefix := ""
			if len(fields) > 1 && !strings.HasSuffix(text, " ") {
				prefix = fields[len(fields)-1]
			}
			return completeFrom(c.shell.commandNames(), prefix)
		}
		return nil, 0
	}

	return completeFrom(c.shell.commandNames(), trimmed)
}

// completeFrom returns suffixes of candidates matching prefix.
func completeFrom(candidates []string, prefix string) ([][]rune, int) {
	var out [][]rune
	for _, candidate := range candidates {
		if !strings.HasPrefix(candidate, prefix) {
			continue
		}
		// A trailing space after a unique completion saves a keystroke and
		// matches readline's built-in behaviour.
		out = append(out, []rune(candidate[len(prefix):]+" "))
	}
	return out, len(prefix)
}

// commandNames lists the names of commands available in the current state.
func (s *Shell) commandNames() []string {
	cmds := s.availableCommands()
	names := make([]string, 0, len(cmds))
	for _, c := range cmds {
		names = append(names, c.name)
	}
	sort.Strings(names)
	return names
}

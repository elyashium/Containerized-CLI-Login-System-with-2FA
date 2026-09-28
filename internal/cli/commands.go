package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/mdp/qrterminal/v3"

	"github.com/shash/cli-login/internal/auth"
)

// command is one shell command.
type command struct {
	name    string
	aliases []string
	summary string
	usage   string
	help    string

	// Visibility rules matching the two command sets in the brief.
	requiresAuth  bool // only when signed in
	requiresGuest bool // only when signed out

	run func(ctx context.Context, s *Shell, args []string) error
}

// commands is the full registry. Order here is the order shown by `help`.
func (s *Shell) commands() []*command {
	return []*command{
		{
			name:          "register",
			summary:       "Create a new account",
			usage:         "register",
			help:          "Prompts for a username and password and creates a new account.\nUsernames are " + auth.UsernameRules + ".",
			requiresGuest: true,
			run:           cmdRegister,
		},
		{
			name:          "login",
			summary:       "Sign in with your username and password",
			usage:         "login",
			help:          "Prompts for your credentials. If two-factor authentication is\nenabled you will also be asked for a 6-digit code from your\nauthenticator app, or one of your recovery codes.",
			requiresGuest: true,
			run:           cmdLogin,
		},
		{
			name:         "whoami",
			summary:      "Show your account and session details",
			usage:        "whoami",
			help:         "Displays your username, registration date, 2FA status, last\nlogin time and when the current session expires.",
			requiresAuth: true,
			run:          cmdWhoami,
		},
		{
			name:         "enable-2fa",
			summary:      "Turn on TOTP two-factor authentication",
			usage:        "enable-2fa",
			help:         "Shows a QR code to scan with Google Authenticator (or any\nTOTP app), then asks for a code to confirm setup. Recovery\ncodes are issued once, at the end of this flow.",
			requiresAuth: true,
			run:          cmdEnable2FA,
		},
		{
			name:         "disable-2fa",
			summary:      "Turn off two-factor authentication",
			usage:        "disable-2fa",
			help:         "Requires your password. Removes the TOTP secret and\ninvalidates all remaining recovery codes.",
			requiresAuth: true,
			run:          cmdDisable2FA,
		},
		{
			name:         "history",
			summary:      "Show recent account activity",
			usage:        "history [count]",
			help:         "Lists recent authentication events recorded for your account,\nincluding failed attempts and lockouts.",
			requiresAuth: true,
			run:          cmdHistory,
		},
		{
			name:         "logout",
			summary:      "End your session",
			usage:        "logout",
			help:         "Revokes the current session server-side and clears the local\nsession cache.",
			requiresAuth: true,
			run:          cmdLogout,
		},
		{
			name:    "help",
			aliases: []string{"?"},
			summary: "Show available commands",
			usage:   "help [command]",
			help:    "With no argument, lists the commands available right now.\nWith a command name, shows detailed help for that command.",
			run:     cmdHelp,
		},
		{
			name:    "exit",
			aliases: []string{"quit"},
			summary: "Quit the program",
			usage:   "exit",
			help:    "Leaves the shell. Your session stays active until it expires,\nso restarting the CLI resumes it.",
			run:     cmdExit,
		},
	}
}

// availableCommands filters the registry by the current auth state.
func (s *Shell) availableCommands() []*command {
	authed := s.isAuthenticated()
	var out []*command
	for _, c := range s.commands() {
		if c.requiresAuth && !authed {
			continue
		}
		if c.requiresGuest && authed {
			continue
		}
		out = append(out, c)
	}
	return out
}

// lookup resolves a name or alias to a command, including commands not
// currently available so dispatch can explain why they cannot be run.
func (s *Shell) lookup(name string) (*command, bool) {
	for _, c := range s.commands() {
		if c.name == name {
			return c, true
		}
		for _, alias := range c.aliases {
			if alias == name {
				return c, true
			}
		}
	}
	return nil, false
}

// ------------------------------------------------------------------ helpers

// askLine prompts for a line of input, mapping cancellation to errAborted.
func (s *Shell) askLine(prompt string) (string, error) {
	line, err := s.reader.ReadLine("  " + prompt)
	if errors.Is(err, ErrInterrupted) {
		s.out.Blank()
		return "", errAborted
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// askSecret prompts for a masked line of input.
func (s *Shell) askSecret(prompt string) (string, error) {
	secret, err := s.reader.ReadPassword("  " + prompt)
	if errors.Is(err, ErrInterrupted) {
		s.out.Blank()
		return "", errAborted
	}
	if err != nil {
		return "", err
	}
	return secret, nil
}

// askConfirm asks a yes/no question, defaulting to no.
func (s *Shell) askConfirm(prompt string) (bool, error) {
	answer, err := s.askLine(prompt + " [y/N]: ")
	if err != nil {
		return false, err
	}
	answer = strings.ToLower(answer)
	return answer == "y" || answer == "yes", nil
}

// errAborted signals the user cancelled a multi-step prompt with Ctrl-C.
var errAborted = errors.New("aborted")

// handlePromptErr converts prompt errors into user feedback, returning true
// when the caller should stop without reporting anything further.
func (s *Shell) handlePromptErr(err error) (bool, error) {
	switch {
	case err == nil:
		return false, nil
	case errors.Is(err, errAborted):
		s.out.Warn("Cancelled.")
		return true, nil
	case errors.Is(err, io.EOF):
		// Input ended mid-prompt; unwind the REPL cleanly.
		return true, io.EOF
	default:
		return true, err
	}
}

// ---------------------------------------------------------------- commands

func cmdRegister(ctx context.Context, s *Shell, _ []string) error {
	s.out.Heading("Create an account")
	s.out.Hint("Username: %s", auth.UsernameRules)
	s.out.Hint("Password: at least %d characters", s.cfg.MinPasswordLength)

	username, err := s.askLine("Username: ")
	if stop, rerr := s.handlePromptErr(err); stop {
		return rerr
	}
	if username == "" {
		s.out.Error("Username cannot be empty.")
		return nil
	}
	// Validate before asking for a password so the user is not made to type a
	// password twice only to be rejected on the username.
	if err := auth.ValidateUsername(username); err != nil {
		s.out.Error("%s", cleanErr(err))
		return nil
	}

	password, err := s.askSecret("Password: ")
	if stop, rerr := s.handlePromptErr(err); stop {
		return rerr
	}
	if err := s.auth.ValidatePassword(password, username); err != nil {
		s.out.Error("%s", cleanErr(err))
		return nil
	}

	confirm, err := s.askSecret("Confirm password: ")
	if stop, rerr := s.handlePromptErr(err); stop {
		return rerr
	}
	if password != confirm {
		s.out.Error("Passwords do not match. Nothing was created.")
		return nil
	}

	user, err := s.auth.Register(ctx, username, password)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrUsernameTaken):
			s.out.Error("The username %q is already taken.", username)
			s.out.Hint("Try a different one.")
		case errors.Is(err, auth.ErrInvalidUsername), errors.Is(err, auth.ErrWeakPassword):
			s.out.Error("%s", cleanErr(err))
		default:
			s.out.Error("Could not create the account: %v", err)
		}
		return nil
	}

	s.out.Blank()
	s.out.Success("Account %s created.", s.out.Bold(user.Username))
	s.out.Hint("Run `login` to sign in.")
	return nil
}

func cmdLogin(ctx context.Context, s *Shell, _ []string) error {
	s.out.Heading("Sign in")

	username, err := s.askLine("Username: ")
	if stop, rerr := s.handlePromptErr(err); stop {
		return rerr
	}
	password, err := s.askSecret("Password: ")
	if stop, rerr := s.handlePromptErr(err); stop {
		return rerr
	}

	result, pending, err := s.auth.Authenticate(ctx, username, password, clientInfo())
	if err != nil {
		s.reportAuthError(err)
		return nil
	}

	// Two-factor challenge.
	if pending != nil {
		result, err = s.promptForSecondFactor(ctx, pending)
		if err != nil {
			if errors.Is(err, errAborted) {
				s.out.Warn("Sign-in cancelled.")
				return nil
			}
			return err
		}
		if result == nil {
			return nil // failure already reported
		}
	}

	s.setSession(result.Token, result.Session, result.User)

	s.out.Blank()
	s.out.Success("Signed in as %s.", s.out.Bold(result.User.Username))
	if result.RecoveryUsed {
		s.out.Warn("You used a recovery code. %d remain.", result.RecoveryLeft)
		if result.RecoveryLeft == 0 {
			s.out.Hint("Run `disable-2fa` then `enable-2fa` to issue a fresh set.")
		}
	}
	s.printUserDetails(ctx, result.Session, result.User, result.PreviousLogin)
	return nil
}

// promptForSecondFactor collects a TOTP or recovery code, allowing a few
// attempts before giving up. Account lockout still applies underneath, so
// retries here cannot be used to brute-force the code.
func (s *Shell) promptForSecondFactor(ctx context.Context, pending *auth.PendingLogin) (*auth.LoginResult, error) {
	const maxTries = 3

	s.out.Blank()
	s.out.Info("Two-factor authentication is enabled for %s.", pending.Username)
	s.out.Hint("Enter the 6-digit code from your authenticator app, or a recovery code.")

	for attempt := 1; attempt <= maxTries; attempt++ {
		code, err := s.askLine("Authentication code: ")
		if err != nil {
			return nil, err
		}
		if code == "" {
			s.out.Error("A code is required.")
			continue
		}

		result, err := s.auth.CompleteMFALogin(ctx, pending, code, clientInfo())
		if err == nil {
			return result, nil
		}

		switch {
		case errors.Is(err, auth.ErrInvalidTOTP):
			if attempt < maxTries {
				s.out.Error("That code is not valid. %d attempt(s) left.", maxTries-attempt)
				s.out.Hint("Codes change every 30 seconds — make sure you are using the current one.")
				continue
			}
			s.out.Error("That code is not valid.")
			s.out.Hint("Run `login` to start again.")
			return nil, nil
		case errors.Is(err, auth.ErrTOTPReplayed):
			s.out.Error("That code has already been used. Wait for the next one.")
			if attempt < maxTries {
				continue
			}
			return nil, nil
		case errors.Is(err, auth.ErrPendingExpired):
			s.out.Error("Sign-in timed out after %s.", auth.FormatDuration(s.cfg.PendingLoginTTL))
			s.out.Hint("Run `login` to start again.")
			return nil, nil
		default:
			s.reportAuthError(err)
			return nil, nil
		}
	}
	return nil, nil
}

func cmdWhoami(ctx context.Context, s *Shell, _ []string) error {
	// refreshSession has already revalidated and reloaded s.user/s.session.
	s.printUserDetails(ctx, s.session, s.user, s.user.LastLoginAt)
	return nil
}

func cmdEnable2FA(ctx context.Context, s *Shell, _ []string) error {
	if s.user.MFAEnabled {
		s.out.Error("Two-factor authentication is already enabled.")
		s.out.Hint("Run `disable-2fa` first if you want to re-enrol a new device.")
		return nil
	}

	enrollment, err := s.auth.BeginMFAEnrollment(ctx, s.user)
	if err != nil {
		s.out.Error("Could not start 2FA setup: %v", err)
		return nil
	}

	s.out.Heading("Enable two-factor authentication")
	s.out.Println("  Scan this QR code with Google Authenticator, 1Password, Authy or")
	s.out.Println("  any other TOTP app:")
	s.out.Blank()

	// Half-block rendering keeps the QR code small enough for a normal
	// terminal window while staying scannable.
	qrterminal.GenerateHalfBlock(enrollment.URI, qrterminal.L, s.out.Writer())

	s.out.Blank()
	s.out.Hint("Can't scan? Enter this key manually:")
	s.out.Field("Secret key", s.out.Cyan(enrollment.Secret))
	s.out.Field("Account", fmt.Sprintf("%s (%s)", s.user.Username, s.cfg.TOTPIssuer))
	s.out.Blank()

	code, err := s.askLine("Enter the 6-digit code shown in your app: ")
	if stop, rerr := s.handlePromptErr(err); stop {
		return rerr
	}

	if err := s.auth.ConfirmMFAEnrollment(ctx, s.user, enrollment, code); err != nil {
		if errors.Is(err, auth.ErrInvalidTOTP) {
			s.out.Error("That code is not valid — two-factor authentication was NOT enabled.")
			s.out.Hint("Check your device's clock is accurate, then run `enable-2fa` again.")
			return nil
		}
		s.out.Error("Could not enable 2FA: %v", err)
		return nil
	}

	s.out.Blank()
	s.out.Success("Two-factor authentication is now enabled.")

	s.out.Heading("Recovery codes")
	s.out.Println("  Store these somewhere safe. Each one can be used once, in place of")
	s.out.Println("  your authenticator code, if you lose access to your device.")
	s.out.Blank()
	for _, recovery := range enrollment.RecoveryCodes {
		s.out.Printf("    %s\n", s.out.Bold(recovery))
	}
	s.out.Blank()
	s.out.Warn("They will not be shown again.")

	// Other sessions were opened under the weaker single-factor policy.
	if revoked, err := s.auth.RevokeOtherSessions(ctx, s.user.ID, s.session.ID); err == nil && revoked > 0 {
		s.out.Info("Signed out %d other session(s).", revoked)
	}
	return nil
}

func cmdDisable2FA(ctx context.Context, s *Shell, _ []string) error {
	if !s.user.MFAEnabled {
		s.out.Error("Two-factor authentication is not enabled.")
		return nil
	}

	s.out.Heading("Disable two-factor authentication")
	s.out.Warn("This removes the second factor protecting your account.")

	confirmed, err := s.askConfirm("Are you sure?")
	if stop, rerr := s.handlePromptErr(err); stop {
		return rerr
	}
	if !confirmed {
		s.out.Info("Left unchanged.")
		return nil
	}

	password, err := s.askSecret("Confirm your password: ")
	if stop, rerr := s.handlePromptErr(err); stop {
		return rerr
	}

	if err := s.auth.DisableMFA(ctx, s.user, password); err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			s.out.Error("That password is not correct. 2FA remains enabled.")
			return nil
		}
		s.out.Error("Could not disable 2FA: %v", err)
		return nil
	}

	s.out.Success("Two-factor authentication disabled. Recovery codes were destroyed.")
	return nil
}

func cmdHistory(ctx context.Context, s *Shell, args []string) error {
	limit := 10
	if len(args) > 0 {
		if n, err := parsePositiveInt(args[0]); err == nil {
			limit = min(n, 50)
		} else {
			s.out.Error("`%s` is not a valid count.", args[0])
			return nil
		}
	}

	events, err := s.auth.RecentEvents(ctx, s.user.ID, limit)
	if err != nil {
		s.out.Error("Could not load activity: %v", err)
		return nil
	}
	if len(events) == 0 {
		s.out.Info("No recorded activity yet.")
		return nil
	}

	s.out.Heading(fmt.Sprintf("Recent activity (latest %d)", len(events)))
	for _, e := range events {
		marker, color := "ok  ", ansiGreen
		if !e.Success {
			marker, color = "fail", ansiRed
		}
		s.out.Printf("  %s  %s  %-16s %s\n",
			s.out.Dim(e.CreatedAt.Local().Format("2006-01-02 15:04:05")),
			s.out.paint(color, marker),
			e.EventType,
			s.out.Dim(e.Detail),
		)
	}
	s.out.Blank()
	return nil
}

func cmdLogout(ctx context.Context, s *Shell, _ []string) error {
	username := s.user.Username
	if err := s.auth.Logout(ctx, s.session, s.user); err != nil {
		s.out.Error("Could not end the session cleanly: %v", err)
		// Still drop local state — the user asked to sign out.
	}
	s.clearLocalSession()
	s.out.Success("Signed out %s.", username)
	return nil
}

func cmdHelp(_ context.Context, s *Shell, args []string) error {
	if len(args) > 0 {
		name := strings.ToLower(args[0])
		cmd, ok := s.lookup(name)
		if !ok {
			s.out.Error("No such command %q.", name)
			return nil
		}
		s.out.Heading(cmd.name)
		s.out.Printf("  %s\n\n", cmd.summary)
		s.out.Printf("  Usage: %s\n\n", s.out.Bold(cmd.usage))
		for _, line := range strings.Split(cmd.help, "\n") {
			s.out.Printf("  %s\n", line)
		}
		if len(cmd.aliases) > 0 {
			s.out.Printf("\n  Aliases: %s\n", strings.Join(cmd.aliases, ", "))
		}
		s.out.Blank()
		return nil
	}

	if s.isAuthenticated() {
		s.out.Heading(fmt.Sprintf("Commands (signed in as %s)", s.user.Username))
	} else {
		s.out.Heading("Commands (not signed in)")
	}
	for _, cmd := range s.availableCommands() {
		s.out.Printf("  %-14s %s\n", s.out.Bold(cmd.name), cmd.summary)
	}
	s.out.Blank()
	s.out.Hint("`help <command>` shows details. Tab completes commands; ↑/↓ browse history.")
	if !s.isAuthenticated() {
		s.out.Hint("More commands become available once you sign in.")
	}
	s.out.Blank()
	return nil
}

func cmdExit(_ context.Context, s *Shell, _ []string) error {
	if s.isAuthenticated() {
		s.out.Info("Leaving %s signed in — the session expires %s.",
			s.user.Username, s.session.ExpiresAt().Local().Format(timeLayout))
		s.out.Hint("Run `logout` before exiting to end it now.")
	}
	s.out.Info("Goodbye.")
	return errExit
}

// ------------------------------------------------------------------ support

// reportAuthError renders an authentication failure in user-facing terms.
func (s *Shell) reportAuthError(err error) {
	var locked *auth.LockedError
	switch {
	case errors.As(err, &locked):
		s.out.Error("Account locked after %d failed attempts.", s.cfg.MaxFailedAttempts)
		s.out.Hint("Try again in %s.", auth.FormatDuration(locked.RetryAfter))
	case errors.Is(err, auth.ErrInvalidCredentials):
		// Deliberately identical whether or not the username exists, so this
		// cannot be used to discover which accounts are registered.
		s.out.Error("Invalid username or password.")
		s.out.Hint("After %d failed attempts the account is locked for %s.",
			s.cfg.MaxFailedAttempts, auth.FormatDuration(s.cfg.LockoutDuration))
	case errors.Is(err, auth.ErrInvalidTOTP):
		s.out.Error("Invalid two-factor code.")
	default:
		s.out.Error("Sign-in failed: %v", err)
	}
}

// cleanErr strips the sentinel prefix from wrapped validation errors so the
// user sees "must be at least 10 characters" rather than the internal
// "password does not meet requirements: must be at least 10 characters".
func cleanErr(err error) string {
	msg := err.Error()
	if _, rest, found := strings.Cut(msg, ": "); found {
		return capitalize(rest)
	}
	return capitalize(msg)
}

// capitalize upper-cases the first rune. It decodes rather than slicing bytes
// so a message starting with a multi-byte character is not corrupted.
func capitalize(s string) string {
	if s == "" {
		return s
	}
	r, size := utf8.DecodeRuneInString(s)
	return string(unicode.ToUpper(r)) + s[size:]
}

func parsePositiveInt(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("not a positive number")
	}
	return n, nil
}

// clientInfo labels the session's origin in the audit trail.
func clientInfo() string { return "cli" }

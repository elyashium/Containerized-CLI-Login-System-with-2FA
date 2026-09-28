package cli

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/shash/cli-login/internal/config"
	"github.com/shash/cli-login/internal/models"
)

// newGuestShell returns a Shell in the signed-out state.
func newGuestShell(t *testing.T) *Shell {
	t.Helper()
	out, _ := newTestOutput()
	return &Shell{
		cfg: &config.Config{
			MinPasswordLength:  10,
			MaxFailedAttempts:  5,
			LockoutDuration:    15 * time.Minute,
			SessionIdleTimeout: 15 * time.Minute,
			TOTPIssuer:         "CLI Login Test",
		},
		out:     out,
		version: "test",
	}
}

// newAuthedShell returns a Shell holding a session for "alice".
func newAuthedShell(t *testing.T) *Shell {
	t.Helper()
	s := newGuestShell(t)
	s.token = "token"
	s.user = &models.User{ID: 1, Username: "alice"}
	s.session = &models.Session{
		ID:                1,
		UserID:            1,
		IdleExpiresAt:     time.Now().Add(15 * time.Minute),
		AbsoluteExpiresAt: time.Now().Add(12 * time.Hour),
	}
	return s
}

// ------------------------------------------------------------ command registry

// TestAvailableCommandsMatchTheBrief pins the two command sets the brief
// specifies. If a command is added or its visibility changes, this fails and
// the requirement has to be reconsidered deliberately.
func TestAvailableCommandsMatchTheBrief(t *testing.T) {
	// Required before login: register, login, help, exit.
	guest := newGuestShell(t).commandNames()
	if want := []string{"exit", "help", "login", "register"}; !equalStrings(guest, want) {
		t.Errorf("signed-out commands = %v, want %v", guest, want)
	}

	// Required after login: whoami, enable-2fa, disable-2fa, logout, help.
	// `exit` and `history` are additions, not replacements.
	authed := newAuthedShell(t).commandNames()
	for _, required := range []string{"whoami", "enable-2fa", "disable-2fa", "logout", "help"} {
		if !contains(authed, required) {
			t.Errorf("%q should be available when signed in; got %v", required, authed)
		}
	}
	// Registering or logging in again while signed in is meaningless.
	for _, forbidden := range []string{"register", "login"} {
		if contains(authed, forbidden) {
			t.Errorf("%q should not be offered while signed in; got %v", forbidden, authed)
		}
	}
}

func TestCommandRegistryIsWellFormed(t *testing.T) {
	seen := map[string]string{}

	for _, cmd := range newGuestShell(t).commands() {
		if cmd.summary == "" || cmd.usage == "" || cmd.help == "" {
			t.Errorf("%s: summary, usage and help must all be set", cmd.name)
		}
		if cmd.run == nil {
			t.Errorf("%s: has no run function", cmd.name)
		}
		if cmd.requiresAuth && cmd.requiresGuest {
			t.Errorf("%s: cannot require both a session and no session", cmd.name)
		}
		// `help <command>` prints the usage line, so it has to name the command.
		if !strings.HasPrefix(cmd.usage, cmd.name) {
			t.Errorf("%s: usage %q should start with the command name", cmd.name, cmd.usage)
		}
		if cmd.name != strings.ToLower(cmd.name) {
			t.Errorf("%s: dispatch lower-cases input, so names must be lower-case", cmd.name)
		}

		for _, name := range append([]string{cmd.name}, cmd.aliases...) {
			if prev, dup := seen[name]; dup {
				t.Errorf("%q is claimed by both %s and %s", name, prev, cmd.name)
			}
			seen[name] = cmd.name
		}
	}
}

func TestLookupResolvesNamesAliasesAndHiddenCommands(t *testing.T) {
	s := newGuestShell(t)

	if cmd, ok := s.lookup("help"); !ok || cmd.name != "help" {
		t.Error("lookup should resolve a command by name")
	}
	if cmd, ok := s.lookup("?"); !ok || cmd.name != "help" {
		t.Error("lookup should resolve the `?` alias to help")
	}
	if cmd, ok := s.lookup("quit"); !ok || cmd.name != "exit" {
		t.Error("lookup should resolve the `quit` alias to exit")
	}
	// Resolving unavailable commands is what lets dispatch say "log in first"
	// instead of "unknown command".
	if cmd, ok := s.lookup("whoami"); !ok || !cmd.requiresAuth {
		t.Error("lookup should find signed-in-only commands while signed out")
	}
	if _, ok := s.lookup("nonsense"); ok {
		t.Error("lookup should not invent commands")
	}
}

// ------------------------------------------------------------------ typo help

func TestSuggestFindsNearMisses(t *testing.T) {
	guest := newGuestShell(t)
	cases := []struct {
		input string
		want  string
	}{
		{"regsiter", "register"},
		{"hlep", "help"},
		{"logn", "login"},
		{"ext", "exit"},
		{"quit", "exit"}, // an alias resolves to the canonical name
		{"xyzzy", ""},    // too far from anything to guess
	}
	for _, tc := range cases {
		if got := guest.suggest(tc.input); got != tc.want {
			t.Errorf("suggest(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}

	// Suggestions are drawn from what the user can actually run, so proposing a
	// signed-in-only command to a guest would be a dead end.
	if got := guest.suggest("whoami"); got != "" {
		t.Errorf("suggest(%q) for a guest = %q, want no suggestion", "whoami", got)
	}
	if got := newAuthedShell(t).suggest("whoam"); got != "whoami" {
		t.Errorf("suggest(%q) when signed in = %q, want %q", "whoam", got, "whoami")
	}
}

func TestEditDistance(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"", "abc", 3},
		{"abc", "", 3},
		{"abc", "abc", 0},
		{"abc", "abd", 1},   // substitution
		{"abc", "abcd", 1},  // insertion
		{"abcd", "abc", 1},  // deletion
		{"hlep", "help", 2}, // transposition costs two edits
		{"kitten", "sitting", 3},
		{"café", "cafe", 1}, // compared by rune, not byte
	}
	for _, tc := range cases {
		if got := editDistance(tc.a, tc.b); got != tc.want {
			t.Errorf("editDistance(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
		// Levenshtein distance is symmetric; an asymmetric result would mean the
		// row-swapping in the implementation is wrong.
		if got := editDistance(tc.b, tc.a); got != tc.want {
			t.Errorf("editDistance(%q, %q) = %d, want %d (should be symmetric)", tc.b, tc.a, got, tc.want)
		}
	}
}

func TestMin3(t *testing.T) {
	cases := [][4]int{
		{1, 2, 3, 1},
		{3, 1, 2, 1},
		{3, 2, 1, 1},
		{2, 2, 2, 2},
		{-1, 0, 1, -1},
	}
	for _, c := range cases {
		if got := min3(c[0], c[1], c[2]); got != c[3] {
			t.Errorf("min3(%d, %d, %d) = %d, want %d", c[0], c[1], c[2], got, c[3])
		}
	}
}

// ---------------------------------------------------------------- completion

func TestCompleteFrom(t *testing.T) {
	candidates := []string{"disable-2fa", "enable-2fa", "exit", "help", "history"}

	cases := []struct {
		prefix string
		want   []string
	}{
		{"", []string{"disable-2fa ", "enable-2fa ", "exit ", "help ", "history "}},
		{"h", []string{"elp ", "istory "}},
		{"hi", []string{"story "}},
		{"history", []string{" "}},
		{"e", []string{"nable-2fa ", "xit "}},
		{"z", nil},
	}
	for _, tc := range cases {
		t.Run("prefix="+tc.prefix, func(t *testing.T) {
			got, offset := completeFrom(candidates, tc.prefix)
			if offset != len(tc.prefix) {
				t.Errorf("offset = %d, want %d", offset, len(tc.prefix))
			}
			if !equalStrings(runesToStrings(got), tc.want) {
				t.Errorf("completions = %q, want %q", runesToStrings(got), tc.want)
			}
		})
	}
}

func TestCommandCompleterCompletesCommandNames(t *testing.T) {
	c := &commandCompleter{shell: newGuestShell(t)}

	got, offset := complete(c, "re")
	if offset != 2 {
		t.Errorf("offset = %d, want 2", offset)
	}
	if !equalStrings(got, []string{"gister "}) {
		t.Errorf("completions for %q = %q, want %q", "re", got, []string{"gister "})
	}

	// Leading whitespace is part of the line but not part of the word.
	if got, _ := complete(c, "  re"); !equalStrings(got, []string{"gister "}) {
		t.Errorf("completions for %q = %q, want %q", "  re", got, []string{"gister "})
	}
}

func TestCommandCompleterCompletesHelpArguments(t *testing.T) {
	c := &commandCompleter{shell: newAuthedShell(t)}

	// `help ` with nothing typed offers every available command.
	got, offset := complete(c, "help ")
	if offset != 0 {
		t.Errorf("offset = %d, want 0", offset)
	}
	if !contains(got, "whoami ") || !contains(got, "logout ") {
		t.Errorf("`help ` should offer every available command, got %q", got)
	}

	// A partially typed argument narrows the list.
	got, offset = complete(c, "help wh")
	if offset != 2 {
		t.Errorf("offset = %d, want 2", offset)
	}
	if !equalStrings(got, []string{"oami "}) {
		t.Errorf("completions for %q = %q, want %q", "help wh", got, []string{"oami "})
	}
}

func TestCommandCompleterOffersNothingForOtherArguments(t *testing.T) {
	c := &commandCompleter{shell: newAuthedShell(t)}
	// `logout` takes no arguments, so completing one would only mislead.
	if got, offset := complete(c, "logout "); got != nil || offset != 0 {
		t.Errorf("completions for %q = %q (offset %d), want none", "logout ", got, offset)
	}
}

func TestCommandNamesAreSortedAndReflectState(t *testing.T) {
	names := newAuthedShell(t).commandNames()
	if !sort.StringsAreSorted(names) {
		t.Errorf("commandNames should be sorted for predictable completion, got %v", names)
	}
	if contains(names, "login") {
		t.Error("commandNames should reflect the current auth state")
	}
}

// --------------------------------------------------------------- shell state

func TestIsAuthenticatedRequiresEveryPiece(t *testing.T) {
	full := newAuthedShell(t)
	if !full.isAuthenticated() {
		t.Fatal("a shell with a token, user and session should be authenticated")
	}

	// A partially populated shell would panic later on a nil dereference, so
	// each field is load-bearing.
	noToken := newAuthedShell(t)
	noToken.token = ""
	noUser := newAuthedShell(t)
	noUser.user = nil
	noSession := newAuthedShell(t)
	noSession.session = nil

	for name, s := range map[string]*Shell{"no token": noToken, "no user": noUser, "no session": noSession} {
		if s.isAuthenticated() {
			t.Errorf("%s: should not count as authenticated", name)
		}
	}
	if newGuestShell(t).isAuthenticated() {
		t.Error("a fresh shell should not be authenticated")
	}
}

func TestPromptReflectsIdentity(t *testing.T) {
	if got := newGuestShell(t).prompt(); got != "auth> " {
		t.Errorf("guest prompt = %q, want %q", got, "auth> ")
	}
	if got := newAuthedShell(t).prompt(); got != "alice@auth> " {
		t.Errorf("signed-in prompt = %q, want %q", got, "alice@auth> ")
	}
}

// ------------------------------------------------------------- small helpers

func TestParsePositiveInt(t *testing.T) {
	valid := map[string]int{"1": 1, "10": 10, "50": 50, "999": 999}
	for in, want := range valid {
		got, err := parsePositiveInt(in)
		if err != nil {
			t.Errorf("parsePositiveInt(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("parsePositiveInt(%q) = %d, want %d", in, got, want)
		}
	}

	for _, in := range []string{"0", "-1", "-10", "", "abc", "1.5", "1e3", " 5", "5 ", "+"} {
		if got, err := parsePositiveInt(in); err == nil {
			t.Errorf("parsePositiveInt(%q) = %d, want an error", in, got)
		}
	}
}

func TestCapitalize(t *testing.T) {
	cases := map[string]string{
		"":                          "",
		"a":                         "A",
		"already Capital":           "Already Capital",
		"must be at least 10 chars": "Must be at least 10 chars",
		"élan":                      "Élan", // a multi-byte first rune must survive
		"1st":                       "1st",
	}
	for in, want := range cases {
		if got := capitalize(in); got != want {
			t.Errorf("capitalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCleanErrStripsTheSentinelPrefix(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "wrapped validation error",
			err:  fmt.Errorf("%w: must be at least 10 characters", errors.New("password does not meet requirements")),
			want: "Must be at least 10 characters",
		},
		{
			name: "unwrapped message",
			err:  errors.New("something went wrong"),
			want: "Something went wrong",
		},
		{
			name: "only the first separator is stripped",
			err:  errors.New("invalid username: must not start with: a dot"),
			want: "Must not start with: a dot",
		},
		{
			name: "a colon with no space is not a prefix separator",
			err:  errors.New("port:8080 is unreachable"),
			want: "Port:8080 is unreachable",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := cleanErr(tc.err); got != tc.want {
				t.Errorf("cleanErr = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClientInfoIsRecorded(t *testing.T) {
	// The value lands in the audit trail, so an empty string would make events
	// harder to interpret later.
	if clientInfo() == "" {
		t.Error("clientInfo should identify the origin of a session")
	}
}

// -------------------------------------------------------------- test helpers

// complete drives commandCompleter.Do with the cursor at the end of text.
func complete(c *commandCompleter, text string) ([]string, int) {
	line := []rune(text)
	out, offset := c.Do(line, len(line))
	return runesToStrings(out), offset
}

func runesToStrings(in [][]rune) []string {
	if in == nil {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, r := range in {
		out = append(out, string(r))
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

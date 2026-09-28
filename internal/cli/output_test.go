package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// newTestOutput returns an Output writing to a buffer with colour forced off,
// so assertions compare plain text rather than escape sequences.
func newTestOutput() (*Output, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	return &Output{w: buf, color: false}, buf
}

func TestOutputMessagesArePrefixedAndTerminated(t *testing.T) {
	cases := []struct {
		name   string
		call   func(o *Output)
		prefix string
	}{
		{"success", func(o *Output) { o.Success("done") }, "✔ done"},
		{"error", func(o *Output) { o.Error("broken") }, "✘ broken"},
		{"warn", func(o *Output) { o.Warn("careful") }, "! careful"},
		{"info", func(o *Output) { o.Info("noted") }, "› noted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o, buf := newTestOutput()
			tc.call(o)
			got := buf.String()
			if !strings.HasPrefix(got, tc.prefix) {
				t.Errorf("got %q, want it to start with %q", got, tc.prefix)
			}
			if !strings.HasSuffix(got, "\n") {
				t.Errorf("got %q, want a trailing newline", got)
			}
		})
	}
}

func TestOutputFormatsArguments(t *testing.T) {
	o, buf := newTestOutput()
	o.Error("Account locked after %d failed attempts.", 5)
	if want := "✘ Account locked after 5 failed attempts.\n"; buf.String() != want {
		t.Errorf("got %q, want %q", buf.String(), want)
	}
}

func TestOutputFieldsAlign(t *testing.T) {
	o, buf := newTestOutput()
	o.Field("Username", "alice")
	o.Field("Two-factor auth", "enabled")

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
	// Values line up only if the label column is padded to a fixed width.
	first := strings.Index(lines[0], "alice")
	second := strings.Index(lines[1], "enabled")
	if first != second {
		t.Errorf("values start at columns %d and %d; they should align", first, second)
	}
}

func TestOutputStylingIsInertWithoutColor(t *testing.T) {
	o, _ := newTestOutput()
	for _, got := range []string{o.Bold("x"), o.Dim("x"), o.Cyan("x")} {
		if got != "x" {
			t.Errorf("styling helper returned %q with colour disabled, want %q", got, "x")
		}
	}
}

func TestOutputStylingWrapsWithColor(t *testing.T) {
	o := &Output{w: &bytes.Buffer{}, color: true}
	got := o.Bold("x")
	if !strings.HasPrefix(got, ansiBold) || !strings.HasSuffix(got, ansiReset) {
		t.Errorf("Bold(%q) = %q, want it wrapped in bold/reset codes", "x", got)
	}
}

func TestShouldUseColorHonoursNoColor(t *testing.T) {
	// https://no-color.org — any value, including empty, disables colour.
	t.Setenv("NO_COLOR", "")
	if shouldUseColor() {
		t.Error("NO_COLOR is set but colour was not disabled")
	}
}

func TestShouldUseColorHonoursDumbTerminal(t *testing.T) {
	t.Setenv("TERM", "dumb")
	if shouldUseColor() {
		t.Error("TERM=dumb should disable colour")
	}
}

func TestHumanDuration(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{0, "0 seconds"},
		{time.Second, "1 second"},
		{45 * time.Second, "45 seconds"},
		{59 * time.Second, "59 seconds"},
		{time.Minute, "1 minute"},
		{90 * time.Second, "1 minute"},
		{2 * time.Minute, "2 minutes"},
		{59 * time.Minute, "59 minutes"},
		{time.Hour, "1 hour"},
		{5 * time.Hour, "5 hours"},
		{23 * time.Hour, "23 hours"},
		{24 * time.Hour, "1 day"},
		{72 * time.Hour, "3 days"},
	}
	for _, tc := range cases {
		if got := humanDuration(tc.in); got != tc.want {
			t.Errorf("humanDuration(%s) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestPluralize(t *testing.T) {
	cases := []struct {
		n    int
		unit string
		want string
	}{
		{0, "minute", "0 minutes"},
		{1, "minute", "1 minute"},
		{2, "minute", "2 minutes"},
		{1, "day", "1 day"},
	}
	for _, tc := range cases {
		if got := pluralize(tc.n, tc.unit); got != tc.want {
			t.Errorf("pluralize(%d, %q) = %q, want %q", tc.n, tc.unit, got, tc.want)
		}
	}
}

func TestRelativeTime(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		at   time.Time
		want string
	}{
		{"just now", now, "just now"},
		{"a few minutes ago", now.Add(-2 * time.Minute), "2 minutes ago"},
		{"hours ago", now.Add(-3 * time.Hour), "3 hours ago"},
		{"in the future", now.Add(15*time.Minute + 30*time.Second), "in 15 minutes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := relativeTime(tc.at); got != tc.want {
				t.Errorf("relativeTime = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFormatTimePairsAbsoluteAndRelative(t *testing.T) {
	// The brief asks for concrete timestamps; the relative hint is an addition,
	// so both parts must be present.
	at := time.Now().Add(-2 * time.Hour)
	got := formatTime(at)

	if !strings.Contains(got, at.Local().Format(timeLayout)) {
		t.Errorf("formatTime = %q, want it to contain the absolute timestamp", got)
	}
	if !strings.Contains(got, "(2 hours ago)") {
		t.Errorf("formatTime = %q, want it to contain the relative hint", got)
	}
}

func TestFormatTimePtr(t *testing.T) {
	if got := formatTimePtr(nil, "first login"); got != "first login" {
		t.Errorf("formatTimePtr(nil) = %q, want the placeholder", got)
	}

	at := time.Now().Add(-time.Hour)
	if got := formatTimePtr(&at, "first login"); got != formatTime(at) {
		t.Errorf("formatTimePtr = %q, want %q", got, formatTime(at))
	}
}

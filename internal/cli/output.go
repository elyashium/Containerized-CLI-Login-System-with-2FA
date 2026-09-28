package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// ANSI colour codes. Kept as a small local helper rather than pulling in a
// colour library for six escape sequences.
const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiBlue   = "\033[34m"
	ansiCyan   = "\033[36m"
)

// Output renders all user-facing text, centralising colour handling and
// message formatting so every command speaks with one voice.
type Output struct {
	w     io.Writer
	color bool
}

// NewOutput builds an Output, disabling colour when the destination is not an
// interactive terminal or when NO_COLOR is set (https://no-color.org).
func NewOutput(w io.Writer) *Output {
	return &Output{w: w, color: shouldUseColor()}
}

func shouldUseColor() bool {
	if _, noColor := os.LookupEnv("NO_COLOR"); noColor {
		return false
	}
	if term := os.Getenv("TERM"); term == "dumb" {
		return false
	}
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// SetWriter redirects output, used once the readline instance is available so
// escape sequences are translated correctly on Windows.
func (o *Output) SetWriter(w io.Writer) { o.w = w }

func (o *Output) paint(code, s string) string {
	if !o.color {
		return s
	}
	return code + s + ansiReset
}

// Printf writes raw formatted text.
func (o *Output) Printf(format string, args ...any) {
	fmt.Fprintf(o.w, format, args...)
}

// Println writes a line.
func (o *Output) Println(args ...any) { fmt.Fprintln(o.w, args...) }

// Blank writes an empty line.
func (o *Output) Blank() { fmt.Fprintln(o.w) }

// Success reports a completed action.
func (o *Output) Success(format string, args ...any) {
	fmt.Fprintf(o.w, "%s %s\n", o.paint(ansiGreen, "✔"), fmt.Sprintf(format, args...))
}

// Error reports a failure the user can act on.
func (o *Output) Error(format string, args ...any) {
	fmt.Fprintf(o.w, "%s %s\n", o.paint(ansiRed, "✘"), fmt.Sprintf(format, args...))
}

// Warn reports something noteworthy that is not a failure.
func (o *Output) Warn(format string, args ...any) {
	fmt.Fprintf(o.w, "%s %s\n", o.paint(ansiYellow, "!"), fmt.Sprintf(format, args...))
}

// Info reports neutral information.
func (o *Output) Info(format string, args ...any) {
	fmt.Fprintf(o.w, "%s %s\n", o.paint(ansiBlue, "›"), fmt.Sprintf(format, args...))
}

// Hint prints dimmed guidance text.
func (o *Output) Hint(format string, args ...any) {
	fmt.Fprintf(o.w, "  %s\n", o.paint(ansiDim, fmt.Sprintf(format, args...)))
}

// Heading prints a bold section title.
func (o *Output) Heading(title string) {
	fmt.Fprintf(o.w, "\n%s\n", o.paint(ansiBold, title))
}

// Field prints one aligned label/value pair.
func (o *Output) Field(label, value string) {
	fmt.Fprintf(o.w, "  %-22s %s\n", o.paint(ansiDim, label), value)
}

// FieldC prints an aligned label/value pair with a coloured value.
func (o *Output) FieldC(label, colorCode, value string) {
	fmt.Fprintf(o.w, "  %-22s %s\n", o.paint(ansiDim, label), o.paint(colorCode, value))
}

// Rule prints a horizontal separator.
func (o *Output) Rule() {
	fmt.Fprintln(o.w, o.paint(ansiDim, strings.Repeat("─", 58)))
}

// Bold returns text styled bold.
func (o *Output) Bold(s string) string { return o.paint(ansiBold, s) }

// Cyan returns text styled cyan.
func (o *Output) Cyan(s string) string { return o.paint(ansiCyan, s) }

// Dim returns dimmed text.
func (o *Output) Dim(s string) string { return o.paint(ansiDim, s) }

// Writer exposes the underlying writer for callers that need it (QR codes).
func (o *Output) Writer() io.Writer { return o.w }

// ---------------------------------------------------------------- formatting

const timeLayout = "2006-01-02 15:04:05 MST"

// formatTime renders an absolute timestamp with a relative hint, e.g.
// "2026-09-28 16:31:02 IST (3 minutes ago)".
func formatTime(t time.Time) string {
	return fmt.Sprintf("%s (%s)", t.Local().Format(timeLayout), relativeTime(t))
}

// formatTimePtr renders an optional timestamp.
func formatTimePtr(t *time.Time, absent string) string {
	if t == nil {
		return absent
	}
	return formatTime(*t)
}

// relativeTime renders how far t is from now in plain language.
func relativeTime(t time.Time) string {
	d := time.Since(t)
	if d < 0 {
		return "in " + humanDuration(-d)
	}
	if d < 5*time.Second {
		return "just now"
	}
	return humanDuration(d) + " ago"
}

// humanDuration renders a duration at a sensible granularity.
func humanDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return pluralize(int(d.Seconds()), "second")
	case d < time.Hour:
		m := int(d.Minutes())
		return pluralize(m, "minute")
	case d < 24*time.Hour:
		h := int(d.Hours())
		return pluralize(h, "hour")
	default:
		days := int(d.Hours() / 24)
		return pluralize(days, "day")
	}
}

func pluralize(n int, unit string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", unit)
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

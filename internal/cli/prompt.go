package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/chzyer/readline"
)

// ErrInterrupted signals Ctrl-C at a prompt.
var ErrInterrupted = errors.New("interrupted")

// lineReader abstracts terminal input so the shell can run either against a
// real interactive terminal (readline: history, tab-completion, masked
// passwords) or against a plain pipe. The pipe implementation is what makes
// the whole REPL scriptable in tests and in the smoke-test target.
type lineReader interface {
	ReadLine(prompt string) (string, error)
	ReadPassword(prompt string) (string, error)
	SetPrompt(prompt string)
	SaveHistory(line string)
	Writer() io.Writer
	Interactive() bool
	Close() error
}

// ---------------------------------------------------------- readline backend

type readlineReader struct {
	rl *readline.Instance
}

// newReadlineReader builds an interactive reader with history and completion.
func newReadlineReader(stateDir string, completer readline.AutoCompleter) (*readlineReader, error) {
	if err := ensureStateDir(stateDir); err != nil {
		return nil, err
	}

	rl, err := readline.NewEx(&readline.Config{
		Prompt:            "auth> ",
		HistoryFile:       historyPath(stateDir),
		HistoryLimit:      500,
		AutoComplete:      completer,
		InterruptPrompt:   "^C",
		EOFPrompt:         "exit",
		HistorySearchFold: true, // case-insensitive Ctrl-R search

		// History is saved explicitly by the shell so that answers to
		// sub-prompts (usernames, 2FA codes) never land in the history file.
		DisableAutoSaveHistory: true,

		FuncFilterInputRune: filterInput,
	})
	if err != nil {
		return nil, fmt.Errorf("initialise interactive prompt: %w", err)
	}
	return &readlineReader{rl: rl}, nil
}

// filterInput drops control characters that would corrupt the line editor.
func filterInput(r rune) (rune, bool) {
	switch r {
	case readline.CharCtrlZ: // Ctrl-Z would suspend the process mid-session
		return r, false
	}
	return r, true
}

func (r *readlineReader) ReadLine(prompt string) (string, error) {
	r.rl.SetPrompt(prompt)
	line, err := r.rl.Readline()
	switch {
	case errors.Is(err, readline.ErrInterrupt):
		return line, ErrInterrupted
	case errors.Is(err, io.EOF):
		return "", io.EOF
	case err != nil:
		return "", err
	}
	return line, nil
}

func (r *readlineReader) ReadPassword(prompt string) (string, error) {
	b, err := r.rl.ReadPassword(prompt)
	switch {
	case errors.Is(err, readline.ErrInterrupt):
		return "", ErrInterrupted
	case errors.Is(err, io.EOF):
		return "", io.EOF
	case err != nil:
		return "", err
	}
	return string(b), nil
}

func (r *readlineReader) SetPrompt(prompt string) { r.rl.SetPrompt(prompt) }
func (r *readlineReader) SaveHistory(line string) { _ = r.rl.SaveHistory(line) }
func (r *readlineReader) Writer() io.Writer       { return r.rl.Stdout() }
func (r *readlineReader) Interactive() bool       { return true }
func (r *readlineReader) Close() error            { return r.rl.Close() }

// -------------------------------------------------------------- pipe backend

// plainReader reads from a non-terminal stdin. Passwords cannot be masked
// here, but there is nothing to mask: input is arriving from a pipe or file,
// not from someone typing at a visible terminal.
type plainReader struct {
	scanner *bufio.Scanner
	out     io.Writer
	echo    bool
}

func newPlainReader(in io.Reader, out io.Writer) *plainReader {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	// Echo input: a pipe does not echo the way a terminal does, so without
	// this the transcript shows prompts with no answers.
	return &plainReader{scanner: scanner, out: out, echo: true}
}

func (p *plainReader) ReadLine(prompt string) (string, error) {
	fmt.Fprint(p.out, prompt)
	if !p.scanner.Scan() {
		if err := p.scanner.Err(); err != nil {
			return "", err
		}
		return "", io.EOF
	}
	line := p.scanner.Text()
	if p.echo {
		// Echo so a piped transcript reads like a real session.
		fmt.Fprintln(p.out, line)
	}
	return line, nil
}

func (p *plainReader) ReadPassword(prompt string) (string, error) {
	fmt.Fprint(p.out, prompt)
	if !p.scanner.Scan() {
		if err := p.scanner.Err(); err != nil {
			return "", err
		}
		return "", io.EOF
	}
	if p.echo {
		fmt.Fprintln(p.out, strings.Repeat("*", 8))
	}
	return p.scanner.Text(), nil
}

func (p *plainReader) SetPrompt(string)   {}
func (p *plainReader) SaveHistory(string) {}
func (p *plainReader) Writer() io.Writer  { return p.out }
func (p *plainReader) Interactive() bool  { return false }
func (p *plainReader) Close() error       { return nil }

// stdinIsTerminal reports whether stdin is an interactive terminal.
func stdinIsTerminal() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

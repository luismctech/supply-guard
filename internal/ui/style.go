package ui

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

var enabled bool

func init() {
	enabled = term.IsTerminal(int(os.Stdout.Fd()))
	if os.Getenv("NO_COLOR") != "" {
		enabled = false
	}
}

// Disable turns off all ANSI styling (used by --quiet or non-table formats).
func Disable() { enabled = false }

// Enabled reports whether color output is active.
func Enabled() bool { return enabled }

func style(code, s string) string {
	if !enabled || s == "" {
		return s
	}
	return fmt.Sprintf("\033[%sm%s\033[0m", code, s)
}

// Base styles
func Bold(s string) string { return style("1", s) }
func Dim(s string) string  { return style("2", s) }

// Foreground colors
func Red(s string) string     { return style("31", s) }
func Green(s string) string   { return style("32", s) }
func Yellow(s string) string  { return style("33", s) }
func Blue(s string) string    { return style("34", s) }
func Magenta(s string) string { return style("35", s) }
func Cyan(s string) string    { return style("36", s) }
func White(s string) string   { return style("37", s) }
func Gray(s string) string    { return style("90", s) }

// Bold + color composites
func BoldRed(s string) string    { return style("1;31", s) }
func BoldGreen(s string) string  { return style("1;32", s) }
func BoldYellow(s string) string { return style("1;33", s) }
func BoldBlue(s string) string   { return style("1;34", s) }
func BoldCyan(s string) string   { return style("1;36", s) }
func BoldWhite(s string) string  { return style("1;37", s) }

// Severity-specific styling
func Critical(s string) string { return style("1;31", s) }
func High(s string) string     { return style("31", s) }
func Medium(s string) string   { return style("33", s) }
func Low(s string) string      { return style("34", s) }
func Info(s string) string     { return style("90", s) }

// Success / Warning / Error for status messages
func Success(s string) string { return style("32", s) }
func Warn(s string) string    { return style("33", s) }
func Error(s string) string   { return style("1;31", s) }

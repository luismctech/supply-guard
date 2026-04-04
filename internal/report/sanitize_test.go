package report

import (
	"testing"
)

func TestSanitize_ControlChars(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"normal text", "hello world", "hello world"},
		{"preserves newline", "line1\nline2", "line1\nline2"},
		{"preserves tab", "col1\tcol2", "col1\tcol2"},
		{"strips null byte", "ab\x00cd", "ab?cd"},
		{"strips ANSI escape", "evil\x1b[31mred\x1b[0m", "evil?[31mred?[0m"},
		{"strips bell", "ding\x07dong", "ding?dong"},
		{"strips carriage return", "over\rwrite", "over?write"},
		{"empty string", "", ""},
		{"only control chars", "\x00\x01\x02\x03", "????"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitize(tt.input)
			if got != tt.want {
				t.Errorf("sanitize(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/garagon/aguara/internal/scanner"
)

func TestTerminalText(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"normal/path with spaces", "normal/path with spaces"},
		{"caf\u00e9/\u65e5\u672c.md", "caf\u00e9/\u65e5\u672c.md"},
		{`C:\Users\dev`, `C:\Users\dev`},
		{"\x1b[2J\x1b]0;x\x07", `\x1b[2J\x1b]0;x\a`},
		{"\r\n\t\b\x00\x7f", `\r\n\t\b\x00\x7f`},
		{"\u009b31m\u009d", `\u009b31m\u009d`},
		{"\x9b\xff", `\x9b\xff`},
		{"\u202e\u2066\u2028", `\u202e\u2066\u2028`},
	} {
		if got := TerminalText(tc.input); got != tc.want || !utf8.ValidString(got) {
			t.Errorf("input=%q got=%q want=%q", tc.input, got, tc.want)
		}
	}
}

func TestTerminalFormatterEscapesDataWithoutChangingResult(t *testing.T) {
	for _, noColor := range []bool{true, false} {
		t.Setenv("NO_COLOR", "")
		bad := "sample\x1b[2J\r\nspoof\u009d"
		name := strings.Repeat("A", 30) + "\t\u00e9BBBB"
		result := &scanner.ScanResult{Target: bad, Findings: []scanner.Finding{
			{RuleID: bad, RuleName: name, FilePath: bad, MatchedText: strings.Repeat("A", 54) + "\t\u00e9BBBB", Description: bad, Remediation: bad, Severity: scanner.SeverityCritical},
			{RuleID: bad, RuleName: name, FilePath: bad, Description: bad, Remediation: bad, Severity: scanner.SeverityHigh},
		}}
		before, _ := json.Marshal(result)
		var buf bytes.Buffer
		f := TerminalFormatter{NoColor: noColor, Verbose: true}
		if err := f.Format(&buf, result); err != nil {
			t.Fatal(err)
		}
		for _, control := range []string{"\x1b[2J", "\r", "\nspoof", "\u009d"} {
			if strings.Contains(buf.String(), control) {
				t.Errorf("control survived: %q", control)
			}
		}
		if !noColor && !strings.Contains(buf.String(), "\x1b[1m") {
			t.Error("trusted style lost")
		}
		if !utf8.Valid(buf.Bytes()) {
			t.Error("rendered output splits a Unicode character")
		}
		after, _ := json.Marshal(result)
		if !bytes.Equal(before, after) {
			t.Error("terminal rendering mutated result")
		}
	}
}

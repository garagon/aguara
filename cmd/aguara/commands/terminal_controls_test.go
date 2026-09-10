package commands

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/garagon/aguara/internal/incident"
	"github.com/stretchr/testify/require"
)

func TestAuditTerminalEscapesUntrustedControls(t *testing.T) {
	for _, noColor := range []bool{true, false} {
		resetFlags()
		flagNoColor = noColor
		res := stubAuditResult(t, 1, 0, 1, 0, 0, 0)
		res.Target = "repo\x1b[2J"
		res.Check.Findings[0].Title = "package\rspoof"
		res.Check.Findings[0].Path = "lock\x1b]0;spoof\x07"
		res.Scan.Findings[0].RuleID = "TEST\x1b[2J"
		res.Scan.Findings[0].RuleName = strings.Repeat("A", 30) + "\t\u00e9BBBB"
		res.Scan.Findings[0].FilePath = "skill\x1b[2J\nspoof.md"
		before, err := json.Marshal(res)
		require.NoError(t, err)
		fetch, restore := captureStdout(t)
		err = writeAuditTerminal(res)
		restore()
		require.NoError(t, err)
		out := fetch()
		require.True(t, utf8.ValidString(out), "rendered output must remain valid UTF-8")
		for _, bad := range []string{"\x1b[2J", "\x1b]", "\x07", "\r", "\b", "\nspoof"} {
			if strings.Contains(out, bad) {
				t.Fatalf("untrusted control %q survived (noColor=%v)", bad, noColor)
			}
		}
		require.Contains(t, out, "AGUARA AUDIT")
		after, err := json.Marshal(res)
		require.NoError(t, err)
		require.True(t, bytes.Equal(before, after), "source JSON unchanged")
		if !noColor {
			require.Contains(t, out, "\x1b[1m", "trusted styling remains")
		}
	}
	resetFlags()
}

func TestCheckTerminalEscapesUntrustedControls(t *testing.T) {
	for _, noColor := range []bool{true, false} {
		resetFlags()
		flagNoColor = noColor
		bad := "data\x1b]0;spoof\x07\r\nspoof"
		res := &incident.CheckResult{Environment: bad, Findings: []incident.Finding{{
			Severity: incident.SevCritical, Title: bad, Path: bad, Detail: bad,
		}}}
		before, err := json.Marshal(res)
		require.NoError(t, err)
		fetch, restore := captureStdout(t)
		err = writeCheckTerminal(res, checkPlan{})
		restore()
		require.NoError(t, err)
		out := fetch()
		for _, control := range []string{"\x1b]", "\x07", "\r", "\nspoof"} {
			if strings.Contains(out, control) {
				t.Fatalf("control survived: %q", control)
			}
		}
		require.Contains(t, out, `\x1b]0;spoof\a\r\nspoof`)
		after, err := json.Marshal(res)
		require.NoError(t, err)
		require.True(t, bytes.Equal(before, after))
	}
	resetFlags()
}

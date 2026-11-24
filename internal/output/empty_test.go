package output_test

import (
	"bytes"
	"testing"

	"github.com/garagon/aguara/internal/output"
	"github.com/garagon/aguara/internal/types"
	"github.com/stretchr/testify/require"
)

// Zero files scanned is not a clean result in any human-readable format.
func TestFormattersSayNothingWasScanned(t *testing.T) {
	cases := []struct {
		name     string
		coverage *types.ScanCoverage
		want     string
	}{
		{"no coverage", nil, "Nothing was scanned: no scannable files under the target"},
		{"path", &types.ScanCoverage{Scope: types.ScanScopePath}, "Nothing was scanned: no scannable files under the target"},
		{"changed", &types.ScanCoverage{Scope: types.ScanScopeChanged}, "Nothing was scanned: no changed files under the target"},
		{"auto", &types.ScanCoverage{Scope: types.ScanScopeAuto}, "Nothing was scanned: the discovered MCP configs"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := &types.ScanResult{RulesLoaded: 70, Coverage: tc.coverage}

			var term bytes.Buffer
			require.NoError(t, (&output.TerminalFormatter{NoColor: true}).Format(&term, result))
			require.Contains(t, term.String(), tc.want)
			require.NotContains(t, term.String(), "No security issues found")

			var md bytes.Buffer
			require.NoError(t, (&output.MarkdownFormatter{}).Format(&md, result))
			require.Contains(t, md.String(), "**Nothing scanned**")
			require.Contains(t, md.String(), tc.want)
			require.NotContains(t, md.String(), "Passed")
		})
	}
}

func TestTerminalFooterNamesChangedScope(t *testing.T) {
	result := &types.ScanResult{FilesScanned: 3, Coverage: &types.ScanCoverage{FilesScanned: 3, Scope: types.ScanScopeChanged}}
	var buf bytes.Buffer
	require.NoError(t, (&output.TerminalFormatter{NoColor: true}).Format(&buf, result))
	require.Contains(t, buf.String(), "3 changed files scanned")
}

package commands

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// A PASS verdict that triage still sends to review because of coverage
// says so on the verdict line; a clean PASS and a findings verdict do not.
func TestAuditVerdictLineFlagsIncompleteCoverage(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	const suffix = "(coverage incomplete, see triage)"

	out := readReport(t, "audit", t.TempDir())
	require.Contains(t, out, "Verdict: PASS (check: 0 critical / 0 warning, scan: 0 critical / 0 high) "+suffix)

	out = readReport(t, "audit", projectWith(t, map[string]string{"gems.locked": "GEM\n  specs:\n"}))
	require.Contains(t, out, "Verdict: PASS")
	require.Contains(t, out, suffix)

	out = readReport(t, "audit", projectWith(t, map[string]string{"README.md": "# app\n"}))
	require.Contains(t, out, "✔ Verdict: PASS")
	require.NotContains(t, out, suffix)

	out = readReport(t, "audit", projectWith(t, map[string]string{
		".claude/settings.json": `{"permissions":{"allow":["Bash(*)"]}}`,
	}))
	require.Contains(t, out, "Verdict: FINDINGS")
	require.NotContains(t, out, suffix)
}

package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// A requirements file with an include the check could not read: the file
// itself was read (it is package evidence), the include is listed in
// coverage.unresolved_includes, and it is reported once as a WARNING
// finding. Triage acts on that finding; coverage does not add a second,
// competing reason for the same include.
func TestUnresolvedIncludeAppearsOnceInCoverageAndFindings(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := projectWith(t, map[string]string{
		"requirements.txt": "-r https://example.com/extra.txt\nflask==3.0.0\n",
	})
	out := filepath.Join(t.TempDir(), "audit.json")
	require.NoError(t, runCLI(t, "audit", dir, "--format", "json", "-o", out))
	raw, err := os.ReadFile(out)
	require.NoError(t, err)

	var result struct {
		Coverage struct {
			PackageEvidence     []map[string]any `json:"package_evidence"`
			UnsupportedEvidence []map[string]any `json:"unsupported_evidence"`
			UnresolvedIncludes  []struct {
				Path     string `json:"path"`
				Line     int    `json:"line"`
				Argument string `json:"argument"`
				Reason   string `json:"reason"`
			} `json:"unresolved_includes"`
		} `json:"coverage"`
		Check struct {
			Findings []struct {
				Severity string `json:"severity"`
				Path     string `json:"path"`
				Line     int    `json:"line"`
			} `json:"findings"`
			Coverage struct {
				UnresolvedIncludes []map[string]any `json:"unresolved_includes"`
			} `json:"coverage"`
		} `json:"check"`
		Triage AuditTriage `json:"triage"`
	}
	require.NoError(t, json.Unmarshal(raw, &result))

	require.Len(t, result.Coverage.PackageEvidence, 1)
	require.Equal(t, "requirements.txt", result.Coverage.PackageEvidence[0]["source"])
	require.Empty(t, result.Coverage.UnsupportedEvidence, "the file was read; the include is not an unsupported file")
	require.Len(t, result.Coverage.UnresolvedIncludes, 1)
	inc := result.Coverage.UnresolvedIncludes[0]
	require.Equal(t, filepath.Join(dir, "requirements.txt"), inc.Path)
	require.Equal(t, 1, inc.Line)
	require.Equal(t, "https://example.com/extra.txt", inc.Argument)
	require.Equal(t, "url", inc.Reason)
	require.Len(t, result.Check.Coverage.UnresolvedIncludes, 1, "the nested check coverage carries it too")

	require.Len(t, result.Check.Findings, 1)
	require.Equal(t, "WARNING", result.Check.Findings[0].Severity)
	require.Equal(t, 1, result.Check.Findings[0].Line)

	require.Equal(t, "review", result.Triage.Decision)
	requireTriageReason(t, result.Triage, "findings_present")
	for _, r := range result.Triage.Reasons {
		require.NotContains(t, []string{"partial_dependency_coverage", "dependency_evidence_not_evaluated"}, r.Kind,
			"the include is reported through its finding, not a second coverage reason")
	}
}

func TestCoverageUnresolvedIncludesIsNeverNull(t *testing.T) {
	raw := checkToFileRaw(t, t.TempDir())
	require.Contains(t, string(raw), `"unresolved_includes": []`)
}

package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// Package findings carry their advisory IDs as a JSON array, so
// consumers need not parse them out of the title.
func TestPackageFindingsListAdvisoryIDs(t *testing.T) {
	isolatePythonCheck(t, "")
	project := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(project, "uv.lock"), []byte(pythonFixtureUVLock), 0o644))
	writeFakeVenv(t, filepath.Join(project, ".venv"), "num2words", "0.5.15")

	var result struct {
		Findings []map[string]json.RawMessage `json:"findings"`
	}
	require.NoError(t, json.Unmarshal(checkToFileRaw(t, project), &result))
	require.Len(t, result.Findings, 2, "lockfile entry and installed copy")
	for _, f := range result.Findings {
		raw, ok := f["advisory_ids"]
		require.True(t, ok, "advisory_ids missing from %v", f)
		var ids []string
		require.NoError(t, json.Unmarshal(raw, &ids))
		require.ElementsMatch(t, []string{"GHSA-jxr6-qrxx-2ph2", "MAL-2025-6794"}, ids)
	}

	// Findings that are not advisory matches have no advisory_ids.
	other := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(other, "requirements.txt"), []byte("-r ../elsewhere.txt\n"), 0o644))
	var warningOnly struct {
		Findings []map[string]json.RawMessage `json:"findings"`
	}
	require.NoError(t, json.Unmarshal(checkToFileRaw(t, other), &warningOnly))
	require.Len(t, warningOnly.Findings, 1)
	require.NotContains(t, warningOnly.Findings[0], "advisory_ids")
}

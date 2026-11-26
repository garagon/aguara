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

// A finding's title names the same advisories as its advisory_ids array,
// in every ecosystem and for installed trees as well as lockfiles.
// @duckdb/node-api 1.3.3 is listed by two embedded advisories.
func TestPackageFindingTitlesNameEveryAdvisoryID(t *testing.T) {
	isolatePythonCheck(t, "")
	project := t.TempDir()
	lock := `{"lockfileVersion":3,"packages":{"":{"name":"x"},"node_modules/@duckdb/node-api":{"version":"1.3.3"}}}`
	require.NoError(t, os.WriteFile(filepath.Join(project, "package-lock.json"), []byte(lock), 0o644))
	installed := filepath.Join(project, "node_modules", "@duckdb", "node-api")
	require.NoError(t, os.MkdirAll(installed, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(installed, "package.json"), []byte(`{"name":"@duckdb/node-api","version":"1.3.3"}`), 0o644))

	var result struct {
		Findings []struct {
			Title       string   `json:"title"`
			AdvisoryIDs []string `json:"advisory_ids"`
		} `json:"findings"`
	}
	require.NoError(t, json.Unmarshal(checkToFileRaw(t, project), &result))
	require.Len(t, result.Findings, 2, "lockfile entry and installed copy")
	for _, f := range result.Findings {
		require.ElementsMatch(t, []string{"GHSA-w62p-hx95-gf2c", "MAL-2025-46992"}, f.AdvisoryIDs, f.Title)
		for _, id := range f.AdvisoryIDs {
			require.Contains(t, f.Title, id)
		}
	}
}

package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/garagon/aguara/internal/rulemeta"
	"github.com/stretchr/testify/require"
)

func writeCLIRule(t *testing.T, dir, id, marker string) string {
	t.Helper()
	rule := fmt.Sprintf(`id: %s
name: "%s marker"
description: "Matches %s"
severity: HIGH
category: custom
targets: ["*.md"]
patterns:
  - type: contains
    value: "%s"
`, id, id, marker, marker)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, id+".yaml"), []byte(rule), 0o600))
	return dir
}

// runCLI executes the root command with args and returns stdout, stderr and
// the command error.
func runCLI(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	resetFlags()
	flagCategory = ""
	out, errOut := new(bytes.Buffer), new(bytes.Buffer)
	rootCmd.SetOut(out)
	rootCmd.SetErr(errOut)
	rootCmd.SetArgs(append(args, "--no-update-check"))
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		resetFlags()
		flagCategory = ""
	})
	err := rootCmd.Execute()
	return out.String(), errOut.String(), err
}

func TestScanRulesFlagRepeatable(t *testing.T) {
	base := t.TempDir()
	packA := writeCLIRule(t, filepath.Join(base, "a"), "PACK_A_001", "pack-a-marker")
	packB := writeCLIRule(t, filepath.Join(base, "b"), "PACK_B_001", "pack-b-marker")
	target := filepath.Join(base, "target")
	require.NoError(t, os.MkdirAll(target, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(target, "x.md"), []byte("pack-a-marker\n\npack-b-marker\n"), 0o600))

	scanIDs := func(args ...string) map[string]int {
		data := scanToFile(t, append([]string{target, "--format", "json", "--project-policy", "ignore"}, args...)...)
		var result struct {
			Findings []struct {
				RuleID string `json:"rule_id"`
			} `json:"findings"`
		}
		require.NoError(t, json.Unmarshal(data, &result))
		ids := map[string]int{}
		for _, f := range result.Findings {
			ids[f.RuleID]++
		}
		return ids
	}

	// A single --rules directory behaves as before.
	single := scanIDs("--rules", packA)
	require.Equal(t, 1, single["PACK_A_001"])
	require.Zero(t, single["PACK_B_001"])

	// Repeating the flag loads every directory instead of keeping the last.
	both := scanIDs("--rules", packA, "--rules", packB)
	require.Equal(t, 1, both["PACK_A_001"])
	require.Equal(t, 1, both["PACK_B_001"])

	listIDs := func(args ...string) map[string]int {
		stdout, _, err := runCLI(t, append([]string{"list-rules", "--format", "json"}, args...)...)
		require.NoError(t, err)
		var listed []rulemeta.Rule
		require.NoError(t, json.Unmarshal([]byte(stdout), &listed))
		seen := map[string]int{}
		for _, r := range listed {
			seen[r.ID]++
		}
		return seen
	}
	listed := listIDs("--rules", packA, "--rules", packB)
	require.Equal(t, 1, listed["PACK_A_001"])
	require.Equal(t, 1, listed["PACK_B_001"])

	// The same directory twice is loaded once.
	require.Equal(t, 1, listIDs("--rules", packA, "--rules", packA+string(filepath.Separator))["PACK_A_001"])
}

package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/garagon/aguara/internal/types"
	"github.com/stretchr/testify/require"
)

func TestScanMCP009Configuration(t *testing.T) {
	for _, tt := range []struct {
		name, content, config string
		count                 int
		severity              types.Severity
	}{
		{"drop", "securityContext:\n  capabilities: {drop: [ALL]}", "", 0, types.SeverityHigh},
		{"sibling", "capabilities: [read_files]\nallow: all", "", 0, types.SeverityHigh},
		{"grant", "capabilities:\n  drop: [ALL]\n  add: [ALL]", "", 1, types.SeverityHigh},
		{"override", "permissions: admin", "rule_overrides:\n  MCP_009:\n    severity: low\n", 1, types.SeverityLow},
		{"disabled override", "permissions: admin", "rule_overrides:\n  MCP_009:\n    disabled: true\n", 0, types.SeverityHigh},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			require.NoError(t, os.WriteFile(path, []byte(tt.content), 0o600))
			if tt.config != "" {
				require.NoError(t, os.WriteFile(filepath.Join(dir, ".aguara.yml"), []byte(tt.config), 0o600))
			}
			data := scanToFile(t, "--format", "json", "--workers", "1", "--project-policy", "trust", path)
			var result types.ScanResult
			require.NoError(t, json.Unmarshal(data, &result))
			count := 0
			for _, f := range result.Findings {
				if f.RuleID == "MCP_009" {
					count++
					require.Equal(t, tt.severity, f.Severity)
				}
			}
			require.Equal(t, tt.count, count)
		})
	}
}

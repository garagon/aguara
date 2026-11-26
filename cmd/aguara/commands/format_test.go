package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// An unsupported --format is a usage error that lists what the command
// can render. It used to fall back to the terminal report with exit 0
// (and for audit, ignore -o as well).
func TestUnsupportedFormatIsRejected(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	project := t.TempDir()
	cases := []struct {
		args      []string
		supported string
	}{
		{[]string{"scan", project, "--format", "xml"}, "terminal, json, sarif, markdown"},
		{[]string{"audit", project, "--format", "xml"}, "terminal, json, sarif, markdown"},
		{[]string{"audit", project, "--format", "html"}, "terminal, json, sarif, markdown"},
		{[]string{"check", project, "--format", "xml"}, "terminal, json, sarif, markdown"},
		{[]string{"check", project, "--format", "csv"}, "terminal, json, sarif, markdown"},
		{[]string{"discover", "--format", "sarif"}, "terminal, json, markdown"},
		{[]string{"list-rules", "--format", "sarif"}, "terminal, json"},
		{[]string{"explain", "CRED_001", "--format", "md"}, "terminal, json"},
		{[]string{"update", "--format", "sarif"}, "terminal, json"},
		{[]string{"clean", "--format", "xml"}, "terminal, json"},
	}
	for _, tc := range cases {
		t.Run(tc.args[0]+" "+tc.args[len(tc.args)-1], func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "report")
			err := runCLI(t, append(tc.args, "-o", out)...)
			requireUsageError(t, err, "unsupported --format", "supported formats are "+tc.supported)
			_, statErr := os.Stat(out)
			require.ErrorIs(t, statErr, os.ErrNotExist, "a rejected format must not write a report")
		})
	}
}

// Format names are case-insensitive and aliases resolve to the canonical
// name for every writer, including audit's JSON switch.
func TestFormatValuesAreNormalized(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	project := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(project, "notes.md"), []byte("# notes\n"), 0o600))

	out := filepath.Join(t.TempDir(), "audit.json")
	require.NoError(t, runCLI(t, "audit", project, "--format", "JSON", "-o", out))
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	var audit map[string]any
	require.NoError(t, json.Unmarshal(data, &audit), "audit --format JSON must emit JSON: %s", data)

	out = filepath.Join(t.TempDir(), "scan.md")
	require.NoError(t, runCLI(t, "scan", project, "--format", "MD", "-o", out))
	data, err = os.ReadFile(out)
	require.NoError(t, err)
	require.Contains(t, string(data), "## Aguara Security Scan")
}

// A trusted .aguara.yml format is scan's own setting: an unsupported
// value fails the scan instead of silently printing the terminal report.
func TestScanRejectsUnsupportedConfigFormat(t *testing.T) {
	project := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(project, ".aguara.yml"), []byte("format: xml\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(project, "notes.md"), []byte("# notes\n"), 0o600))
	err := runCLI(t, "scan", project, "--project-policy", "trust")
	requireUsageError(t, err, `unsupported .aguara.yml format "xml"`, "supported formats are terminal, json, sarif, markdown")
}

// audit only borrows the scan config's format key: a value audit cannot
// render is reported and the audit keeps its own --format.
func TestAuditIgnoresScanOnlyConfigFormat(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	project := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(project, ".aguara.yml"), []byte("format: xml\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(project, "notes.md"), []byte("# notes\n"), 0o600))
	out := filepath.Join(t.TempDir(), "audit.txt")
	require.NoError(t, runCLI(t, "audit", project, "--project-policy", "trust", "-o", out))
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	require.Contains(t, string(data), "AGUARA AUDIT")
}

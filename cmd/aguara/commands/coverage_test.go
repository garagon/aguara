package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const uvLockWithKnownMaliciousVersion = `version = 1
requires-python = ">=3.11"

[[package]]
name = "litellm"
version = "1.82.7"
source = { registry = "https://pypi.org/simple" }
`

// projectWith creates a project directory holding the given files.
// A value starting with "@" copies that repository fixture instead.
func projectWith(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if len(content) > 0 && content[0] == '@' {
			data, err := os.ReadFile(content[1:])
			require.NoError(t, err)
			content = string(data)
		}
		path := filepath.Join(dir, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
	return dir
}

const packageLockFixture = "@../../../internal/packagecheck/testdata/package-lock-clean/package-lock.json"

func TestScanJSONReportsCoverage(t *testing.T) {
	dir := projectWith(t, map[string]string{"a.md": "# a\n", "b.md": "# b\n"})
	data := scanToFile(t, dir, "--format", "json")
	var result struct {
		Coverage *struct {
			FilesScanned int    `json:"files_scanned"`
			Scope        string `json:"scope"`
		} `json:"coverage"`
	}
	require.NoError(t, json.Unmarshal(data, &result))
	require.NotNil(t, result.Coverage, "scan JSON must carry a coverage block: %s", data)
	require.Equal(t, 2, result.Coverage.FilesScanned)
	require.Equal(t, "path", result.Coverage.Scope)

	repo := commitRepo(t, map[string]string{"a.md": "# a\n"})
	require.NoError(t, os.WriteFile(filepath.Join(repo, "a.md"), []byte("# changed\n"), 0o644))
	data = scanToFile(t, repo, "--format", "json", "--changed")
	require.NoError(t, json.Unmarshal(data, &result))
	require.Equal(t, 1, result.Coverage.FilesScanned)
	require.Equal(t, "changed", result.Coverage.Scope)
}

func TestCheckJSONReportsReadAndUnsupportedEvidence(t *testing.T) {
	dir := projectWith(t, map[string]string{
		"package-lock.json":        packageLockFixture,
		"backend/uv.lock":          uvLockWithKnownMaliciousVersion,
		"backend/requirements.txt": "litellm==1.82.7\n",
	})
	raw := checkToFileRaw(t, dir)
	var result struct {
		Coverage struct {
			PackageEvidence []struct {
				Ecosystem    string `json:"ecosystem"`
				Source       string `json:"source"`
				Targets      int    `json:"targets"`
				PackagesRead int    `json:"packages_read"`
			} `json:"package_evidence"`
			UnsupportedEvidence []struct {
				Path      string `json:"path"`
				Kind      string `json:"kind"`
				Ecosystem string `json:"ecosystem"`
			} `json:"unsupported_evidence"`
		} `json:"coverage"`
	}
	require.NoError(t, json.Unmarshal(raw, &result))
	require.Len(t, result.Coverage.PackageEvidence, 1)
	require.Equal(t, "npm", result.Coverage.PackageEvidence[0].Ecosystem)
	require.Equal(t, "package-lock.json", result.Coverage.PackageEvidence[0].Source)
	require.Equal(t, 1, result.Coverage.PackageEvidence[0].Targets)
	require.Equal(t, 2, result.Coverage.PackageEvidence[0].PackagesRead)

	require.Len(t, result.Coverage.UnsupportedEvidence, 2)
	kinds := map[string]string{}
	for _, u := range result.Coverage.UnsupportedEvidence {
		rel, err := filepath.Rel(dir, u.Path)
		require.NoError(t, err)
		kinds[filepath.ToSlash(rel)] = u.Kind
		require.Equal(t, "PyPI", u.Ecosystem)
	}
	require.Equal(t, map[string]string{
		"backend/uv.lock":          "uv.lock",
		"backend/requirements.txt": "requirements.txt",
	}, kinds)
}

func TestCheckCoverageArraysAreNeverNull(t *testing.T) {
	raw := checkToFileRaw(t, t.TempDir())
	require.Contains(t, string(raw), `"package_evidence": []`)
	require.Contains(t, string(raw), `"unsupported_evidence": []`)
	require.NotContains(t, string(raw), "null")
}

// An explicit --ecosystem limits the unsupported list to what was asked.
func TestCheckExplicitEcosystemScopesUnsupportedEvidence(t *testing.T) {
	dir := projectWith(t, map[string]string{
		"go.sum":  "@../../../internal/packagecheck/testdata/go-clean/go.sum",
		"uv.lock": uvLockWithKnownMaliciousVersion,
	})
	raw := checkToFileRaw(t, dir, "--ecosystem", "go")
	require.Contains(t, string(raw), `"unsupported_evidence": []`)

	raw = checkToFileRaw(t, dir, "--ecosystem", "python")
	require.Contains(t, string(raw), `"kind": "uv.lock"`)
}

func TestAuditJSONReportsCoverage(t *testing.T) {
	dir := projectWith(t, map[string]string{
		"README.md":         "# project\n",
		"package-lock.json": packageLockFixture,
		"uv.lock":           uvLockWithKnownMaliciousVersion,
	})
	out := filepath.Join(t.TempDir(), "audit.json")
	require.NoError(t, runCLI(t, "audit", dir, "--format", "json", "-o", out))
	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	var result struct {
		Coverage struct {
			FilesScanned        int              `json:"files_scanned"`
			PackageEvidence     []map[string]any `json:"package_evidence"`
			UnsupportedEvidence []map[string]any `json:"unsupported_evidence"`
		} `json:"coverage"`
		Check struct {
			Coverage map[string]any `json:"coverage"`
		} `json:"check"`
		Scan struct {
			Coverage map[string]any `json:"coverage"`
		} `json:"scan"`
	}
	require.NoError(t, json.Unmarshal(raw, &result))
	require.Equal(t, 3, result.Coverage.FilesScanned)
	require.Len(t, result.Coverage.PackageEvidence, 1)
	require.Len(t, result.Coverage.UnsupportedEvidence, 1)
	require.Equal(t, "uv.lock", result.Coverage.UnsupportedEvidence[0]["kind"])
	require.NotNil(t, result.Check.Coverage, "the nested check result carries its coverage too")
	require.NotNil(t, result.Scan.Coverage, "the nested scan result carries its coverage too")
}

func TestCheckTerminalReportsCoverage(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := projectWith(t, map[string]string{
		"package-lock.json": packageLockFixture,
		"backend/uv.lock":   uvLockWithKnownMaliciousVersion,
	})
	out := filepath.Join(t.TempDir(), "check.txt")
	require.NoError(t, runCLI(t, "check", dir, "-o", out))
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	require.Contains(t, string(data), "Coverage: npm package-lock.json: 2 packages")
	require.Contains(t, string(data), "Not evaluated: backend/uv.lock")
}

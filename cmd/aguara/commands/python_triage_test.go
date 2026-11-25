package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const uvLockFixture = "@../../../internal/packagecheck/testdata/python-uv/uv.lock"

// A requirements file whose entries are all unpinned was read, but only
// advisories covering every version could be matched for it: the audit
// asks for review instead of clearing installation.
func TestAuditReviewsDependencyFilesWithNoPinnedEntry(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := projectWith(t, map[string]string{"requirements.txt": "requests>=2\nflask\n"})

	result := auditToFile(t, dir)
	require.Equal(t, "pass", result.Verdict.Status)
	require.Equal(t, "review", result.Triage.Decision)
	require.Equal(t, "Some dependency entries are not pinned to one version, so the audit cannot clear dependency installation.", result.Triage.Summary)
	requireTriageReason(t, result.Triage, "unpinned_dependency_evidence")
	for _, r := range result.Triage.Reasons {
		if r.Kind == "unpinned_dependency_evidence" {
			require.Equal(t, "warning", r.Severity)
			require.Equal(t, "2 of 2 entries in requirements.txt are not pinned to one version, so only advisories covering every version were checked for them.", r.Message)
		}
	}
	require.False(t, result.Plan.CanInstallDependencies)
	require.Equal(t, 2, result.Coverage.PackageEvidence[0].Unpinned)

	out := readReport(t, "audit", dir)
	require.Contains(t, out, "(coverage incomplete, see triage)")
	require.Contains(t, out, "2 Python dependencies are not pinned to one version")
	require.Contains(t, out, "No pinned versions were found, so no exact version was checked")
	require.NotContains(t, out, "✔ No known-compromised packages")
	require.NotContains(t, out, "\x1b[")

	out = readReport(t, "check", dir)
	require.Contains(t, out, "Coverage: PyPI requirements.txt: 2 packages (2 unpinned)")
	require.Contains(t, out, "No pinned versions were found")
}

// A constraints file installs nothing: a range in it leaves no
// dependency unchecked, whether the file is found by name or reached
// through a -c include, so it never triggers the unpinned review.
func TestConstraintRangesDoNotCountAsUnpinnedDependencies(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cases := map[string]map[string]string{
		"pin plus constraints file": {
			"requirements.txt": "flask==3.0.0\n",
			"constraints.txt":  "urllib3<2\n",
		},
		"constraints file only": {
			"constraints.txt": "urllib3<2\n",
		},
		"constraint included with -c": {
			"requirements.txt": "flask==3.0.0\n-c constraints.txt\n",
			"constraints.txt":  "urllib3<2\n",
		},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			result := auditToFile(t, projectWith(t, files))
			require.Equal(t, "proceed", result.Triage.Decision)
			require.True(t, result.Plan.CanInstallDependencies)
			for _, r := range result.Triage.Reasons {
				require.NotEqual(t, "unpinned_dependency_evidence", r.Kind, r.Message)
			}
			for _, e := range result.Check.Ecosystems {
				require.Zero(t, e.Unpinned, "%s: constraint entries are not unpinned dependencies", e.Source)
			}
		})
	}
}

// Any installable entry without an exact pin leaves a version nothing
// checked, whatever else the file pins; an entry that a pin of the same
// name covers (in the file or through -c) does not, and neither does a
// constraint.
func TestAuditUnpinnedRuleCountsEveryUnpinnedEntry(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cases := []struct {
		name     string
		files    map[string]string
		decision string
		message  string
	}{
		{
			name:     "one pin plus three ranges",
			files:    map[string]string{"requirements.txt": "flask==3.0.0\nrequests>=2\nclick\njinja2~=3.1\n"},
			decision: "review",
			message:  "3 of 4 entries in requirements.txt are not pinned to one version, so only advisories covering every version were checked for them.",
		},
		{
			name:     "clean uv.lock plus a range beside an unrelated pin",
			files:    map[string]string{"uv.lock": uvLockFixture, "requirements.txt": "requests>=2\nflask==3.0.0\n"},
			decision: "review",
			message:  "1 of 2 entries in requirements.txt is not pinned to one version, so only advisories covering every version were checked for it.",
		},
		{
			name: "range pinned by a -c constraint",
			files: map[string]string{
				"requirements.txt": "requests\n-c constraints.txt\n",
				"constraints.txt":  "requests==2.31.0\n",
			},
			decision: "proceed",
		},
		{
			name:     "range pinned in the same file",
			files:    map[string]string{"requirements.txt": "Requests>=2\nrequests==2.31.0\n"},
			decision: "proceed",
		},
		{
			name:     "constraints file with ranges",
			files:    map[string]string{"requirements.txt": "flask==3.0.0\n", "constraints.txt": "urllib3<2\nidna>=3\n"},
			decision: "proceed",
		},
		{
			name:     "all pinned",
			files:    map[string]string{"requirements.txt": "flask==3.0.0\nrequests===2.31.0\n"},
			decision: "proceed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := auditToFile(t, projectWith(t, tc.files))
			require.Equal(t, tc.decision, result.Triage.Decision)
			require.Equal(t, tc.decision == "proceed", result.Plan.CanInstallDependencies)
			var got string
			for _, r := range result.Triage.Reasons {
				if r.Kind == "unpinned_dependency_evidence" {
					require.Equal(t, "warning", r.Severity)
					got = r.Message
				}
			}
			require.Equal(t, tc.message, got)
		})
	}
}

// Tool-generated lockfiles stay `proceed`: workspace members, editable
// installs, local paths and git checkouts have no index version by
// design and are not index requirements, so they never count as
// unpinned.
func TestResolvedLockfilesWithNonIndexEntriesProceed(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	const uvWorkspace = `version = 1
requires-python = ">=3.11"

[manifest]
members = ["app", "shared"]

[[package]]
name = "app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "shared" }, { name = "requests" }, { name = "gitdep" }, { name = "localdep" }]

[[package]]
name = "shared"
version = "0.2.0"
source = { editable = "packages/shared" }

[[package]]
name = "gitdep"
version = "1.0.0"
source = { git = "https://github.com/example/gitdep?rev=v1#0123456789abcdef0123456789abcdef01234567" }

[[package]]
name = "localdep"
version = "0.3.0"
source = { directory = "vendor/localdep" }

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
`
	const pipfileLock = `{
  "_meta": {"hash": {"sha256": "0000"}, "pipfile-spec": 6, "requires": {}, "sources": [{"name": "pypi", "url": "https://pypi.org/simple", "verify_ssl": true}]},
  "default": {
    "requests": {"hashes": ["sha256:0000"], "index": "pypi", "version": "==2.31.0"},
    "mylib": {"editable": true, "path": "."},
    "gitdep": {"git": "https://github.com/example/gitdep.git", "ref": "0123456789abcdef0123456789abcdef01234567"}
  },
  "develop": {
    "pytest": {"hashes": ["sha256:0000"], "index": "pypi", "version": "==8.2.0"}
  }
}
`
	cases := map[string]map[string]string{
		"uv.lock with workspace, editable, git and directory entries": {"uv.lock": uvWorkspace},
		"poetry.lock":  {"poetry.lock": "@../../../internal/packagecheck/testdata/python-poetry/poetry.lock"},
		"pdm.lock":     {"pdm.lock": "@../../../internal/packagecheck/testdata/python-pdm/pdm.lock"},
		"Pipfile.lock": {"Pipfile.lock": pipfileLock},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			result := auditToFile(t, projectWith(t, files))
			require.Equal(t, "proceed", result.Triage.Decision)
			require.True(t, result.Plan.CanInstallDependencies)
			require.Len(t, result.Check.Ecosystems, 1)
			require.Zero(t, result.Check.Ecosystems[0].Unpinned)
			require.NotZero(t, result.Check.Ecosystems[0].PackagesRead)
		})
	}
}

// A Python lockfile that was evaluated clean does not cover an
// unsupported dependency file elsewhere in the project.
func TestAuditReviewsCleanUVLockBesideUnsupportedFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := projectWith(t, map[string]string{
		"uv.lock":       uvLockFixture,
		"web/deno.lock": denoLockFixture,
	})
	result := auditToFile(t, dir)
	require.Empty(t, result.Check.Findings)
	require.Equal(t, "review", result.Triage.Decision)
	requireTriageReason(t, result.Triage, "partial_dependency_coverage")
	require.False(t, result.Plan.CanInstallDependencies)
	require.Len(t, result.Coverage.PackageEvidence, 1)
	require.Equal(t, "uv.lock", result.Coverage.PackageEvidence[0].Source)
}

// -o and --format apply to the Python findings and terminal lines: the
// file gets the report in the selected format, without color codes, and
// stdout stays empty.
func TestPythonReportsHonorOutputAndFormat(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := projectWith(t, map[string]string{
		"uv.lock":          uvLockWithKnownMaliciousVersion,
		"requirements.txt": "-r missing.txt\nrequests>=2\n",
	})
	for _, command := range []string{"check", "audit"} {
		t.Run(command, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "report.txt")
			var err error
			stdout := captureStdoutBytes(t, func() { err = runCLI(t, command, dir, "-o", out) })
			require.NoError(t, err)
			require.Empty(t, string(stdout))
			data, readErr := os.ReadFile(out)
			require.NoError(t, readErr)
			text := string(data)
			require.NotContains(t, text, "\x1b[")
			require.Contains(t, text, "litellm 1.82.7 is a known compromised PyPI package")
			require.Contains(t, text, filepath.Join(dir, "uv.lock")+":", "findings carry their file:line location")
			require.Contains(t, text, "requirements.txt includes missing.txt, which was not checked")
			require.Contains(t, text, "1 Python dependency is not pinned to one version")

			jsonOut := filepath.Join(t.TempDir(), "report.json")
			require.NoError(t, runCLI(t, command, dir, "--format", "json", "-o", jsonOut))
			raw, readErr := os.ReadFile(jsonOut)
			require.NoError(t, readErr)
			var decoded map[string]any
			require.NoError(t, json.Unmarshal(raw, &decoded))
			require.Contains(t, string(raw), `"advisory_ids"`)
			require.Contains(t, string(raw), `"unresolved_includes"`)
		})
	}
}

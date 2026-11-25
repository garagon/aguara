package commands

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/incident"
	"github.com/garagon/aguara/internal/packagecheck"
	"github.com/stretchr/testify/require"
)

// num2words 0.5.15 is in the embedded intelligence under two advisory
// IDs; litellm 1.82.7 is on the hand-curated list.
const pythonFixtureUVLock = `version = 1
revision = 3
requires-python = ">=3.10"

[[package]]
name = "demo"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "num2words" },
    { name = "six" },
]

[[package]]
name = "Num2Words"
version = "0.5.15"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "six"
version = "1.16.0"
source = { registry = "https://pypi.org/simple" }
`

// isolatePythonCheck gives the test an empty HOME (no cached intel, no
// host artifacts) and a controlled VIRTUAL_ENV.
func isolatePythonCheck(t *testing.T, virtualEnv string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("VIRTUAL_ENV", virtualEnv)
	t.Setenv("AGUARA_NO_UPDATE_CHECK", "1")
}

// writeFakeVenv creates a PEP 405 environment whose site-packages holds
// one dist-info directory. Nothing is installed or executed.
func writeFakeVenv(t *testing.T, root, name, version string) string {
	t.Helper()
	site := filepath.Join(root, "lib", "python3.12", "site-packages")
	dist := filepath.Join(site, name+"-"+version+".dist-info")
	require.NoError(t, os.MkdirAll(dist, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "pyvenv.cfg"), []byte("home = /usr/bin\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dist, "METADATA"),
		[]byte("Metadata-Version: 2.1\nName: "+name+"\nVersion: "+version+"\n"), 0o644))
	return site
}

func evidence(r *incident.CheckResult) (ecosystems []packagecheck.EcosystemResult, findings []incident.Finding) {
	ecosystems = append(ecosystems, r.Ecosystems...)
	findings = append(findings, r.Findings...)
	sort.Slice(ecosystems, func(i, j int) bool { return ecosystems[i].Path < ecosystems[j].Path })
	sort.Slice(findings, func(i, j int) bool { return findings[i].Location() < findings[j].Location() })
	return ecosystems, findings
}

func TestCheckAndAuditReadTheSameEvidenceForADirectory(t *testing.T) {
	outsideVenv := t.TempDir()
	writeFakeVenv(t, outsideVenv, "litellm", "1.82.7")
	isolatePythonCheck(t, outsideVenv)

	project := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(project, "uv.lock"), []byte(pythonFixtureUVLock), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(project, "requirements.txt"), []byte("six==1.16.0\nrequests>=2\n"), 0o644))
	venvSite := writeFakeVenv(t, filepath.Join(project, ".venv"), "num2words", "0.5.15")

	checked := checkToFile(t, project)
	audited := auditToFile(t, project)
	checkEco, checkFindings := evidence(checked)
	auditEco, auditFindings := evidence(audited.Check)
	require.Equal(t, checkEco, auditEco, "check <dir> and audit <dir> must read the same evidence")
	require.Equal(t, checkFindings, auditFindings)

	sources := map[string]packagecheck.EcosystemResult{}
	for _, e := range checkEco {
		sources[e.Source] = e
		require.NotContains(t, e.Path, outsideVenv, "an unrelated VIRTUAL_ENV is not read for an explicit path")
	}
	require.Contains(t, sources, "uv.lock")
	require.Contains(t, sources, "requirements.txt")
	require.Equal(t, 1, sources["requirements.txt"].Unpinned)
	require.Equal(t, venvSite, sources["site-packages"].Path)

	require.Len(t, checkFindings, 2, "the lockfile pin and the installed copy are separate evidence")
	var lock incident.Finding
	for _, f := range checkFindings {
		require.Equal(t, incident.SevCritical, f.Severity)
		require.NotContains(t, f.Title, "litellm")
		if strings.HasSuffix(f.Path, "uv.lock") {
			lock = f
		}
	}
	require.Equal(t, 14, lock.Line, "the [[package]] entry that matched")
	require.Contains(t, lock.Title, "Num2Words 0.5.15 is a known compromised PyPI package")
	require.Contains(t, lock.Title, "GHSA-jxr6-qrxx-2ph2")
	require.Contains(t, lock.Title, "MAL-2025-6794")
	require.Equal(t, "stop", audited.Triage.Decision)
}

// packageEvidence reduces findings to what identifies the evidence:
// severity, title (package, version, advisory IDs) and location.
// Remediation wording differs between the installed-environment check
// and the environment evidence and is not compared.
func packageEvidence(findings []incident.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Severity+" "+f.Title+" @ "+f.Location())
	}
	sort.Strings(out)
	return out
}

func TestCheckAndAuditWithoutPathBothReadTheActiveEnvironment(t *testing.T) {
	activeVenv := t.TempDir()
	writeFakeVenv(t, activeVenv, "num2words", "0.5.15")
	isolatePythonCheck(t, activeVenv)
	for name, files := range map[string]map[string]string{
		"python project":     {"requirements.txt": "six==1.16.0\n"},
		"go project":         {"go.sum": "golang.org/x/text v0.3.0 h1:abc=\n"},
		"no evidence at all": {},
	} {
		t.Run(name, func(t *testing.T) {
			project := t.TempDir()
			for f, content := range files {
				require.NoError(t, os.WriteFile(filepath.Join(project, f), []byte(content), 0o644))
			}
			t.Chdir(project)

			checked := checkToFile(t)
			audited := auditToFile(t)
			checkEco, checkFindings := evidence(checked)
			auditEco, auditFindings := evidence(audited.Check)
			require.Equal(t, checkEco, auditEco, "same dependency files and environments")
			require.Equal(t, packageEvidence(checkFindings), packageEvidence(auditFindings))
			require.Len(t, auditFindings, 1)
			require.Contains(t, auditFindings[0].Path, activeVenv)
			require.Equal(t, "stop", audited.Triage.Decision, "audit with no path no longer passes an active compromised environment")
		})
	}
}

func TestCheckWithoutPathKeepsTheInstalledEnvironmentFallback(t *testing.T) {
	// No dependency files: `aguara check` keeps its historical
	// installed-environment check (host artifacts included), now
	// without duplicating the active environment; audit reads the same
	// active environment as environment evidence.
	activeVenv := t.TempDir()
	writeFakeVenv(t, activeVenv, "num2words", "0.5.15")
	isolatePythonCheck(t, activeVenv)
	t.Chdir(t.TempDir())

	checked := checkToFile(t)
	require.NotEmpty(t, checked.Credentials, "the legacy check still reports credential files")
	require.Len(t, checked.Ecosystems, 1)
	require.Len(t, checked.Findings, 1)
	require.Contains(t, checked.Findings[0].Title, "num2words 0.5.15")

	audited := auditToFile(t)
	require.Len(t, audited.Check.Findings, 1)
	require.Equal(t, checked.Findings[0].Path, audited.Check.Findings[0].Path)
	require.Equal(t, checked.Findings[0].Title, audited.Check.Findings[0].Title, "same package, same advisory IDs")
	require.Contains(t, checked.Findings[0].Title, "GHSA-jxr6-qrxx-2ph2, MAL-2025-6794")

	// A Python-only project (here a requirements file) still gets the
	// installed-environment check it got before Python dependency files
	// were read, plus the new dependency-file evidence.
	project := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(project, "requirements.txt"), []byte("six==1.16.0\n"), 0o644))
	t.Chdir(project)
	checked = checkToFile(t)
	require.NotEmpty(t, checked.Credentials, "legacy installed-environment check still runs")
	sources := []string{}
	for _, e := range checked.Ecosystems {
		sources = append(sources, e.Source)
	}
	require.ElementsMatch(t, []string{"site-packages", "requirements.txt"}, sources, "the active environment is not read twice")
}

func TestCheckPythonEnvironmentBoundaries(t *testing.T) {
	isolatePythonCheck(t, "")
	outside := t.TempDir()
	writeFakeVenv(t, outside, "num2words", "0.5.15")

	// A .venv symlink that leaves the project is not project evidence.
	project := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(project, ".venv")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	require.NoError(t, os.WriteFile(filepath.Join(project, "README.md"), []byte("x"), 0o644))
	result := checkToFile(t, project)
	require.Empty(t, result.Findings)
	require.Empty(t, result.Ecosystems)

	// VIRTUAL_ENV inside the target is read even with an explicit path.
	inner := filepath.Join(project, "envs", "py312")
	writeFakeVenv(t, inner, "num2words", "0.5.15")
	t.Setenv("VIRTUAL_ENV", inner)
	result = checkToFile(t, project)
	require.Len(t, result.Findings, 1)
	require.Contains(t, result.Findings[0].Path, inner)

	// A directory that is not a virtual environment is ignored.
	plain := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(plain, "venv", "lib", "python3.12", "site-packages", "num2words-0.5.15.dist-info"), 0o755))
	require.Empty(t, discoverPythonEnvironments(plain, false))

	// The target itself may be the environment.
	envs := discoverPythonEnvironments(outside, false)
	require.Len(t, envs, 1)
	require.Equal(t, "target", envs[0].origin)
}

func TestCheckExplicitPythonEcosystemReadsDependencyFiles(t *testing.T) {
	isolatePythonCheck(t, "")
	project := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(project, "uv.lock"), []byte(pythonFixtureUVLock), 0o644))
	result := checkToFile(t, "--ecosystem", "python", "--path", project)
	found := false
	for _, f := range result.Findings {
		found = found || strings.Contains(f.Title, "Num2Words 0.5.15")
	}
	require.True(t, found, "--ecosystem python covers Python lockfiles")

	// An installed tree passed explicitly keeps the historical shape.
	site := writeFakeVenv(t, t.TempDir(), "six", "1.16.0")
	result = checkToFile(t, "--ecosystem", "python", "--path", site)
	require.Len(t, result.Ecosystems, 1)
	require.Equal(t, "site-packages", result.Ecosystems[0].Source)
}

func TestCheckPythonLockfileTerminalLabel(t *testing.T) {
	isolatePythonCheck(t, "")
	project := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(project, "poetry.lock"), []byte("[[package]]\nname = \"six\"\nversion = \"1.16.0\"\n"), 0o644))
	plan, err := buildCheckPlan(nil, project)
	require.NoError(t, err)
	require.Equal(t, ecoPythonLock, plan.singleEcoToken())
	require.Equal(t, "Python dependencies", singleEcoEnvLabel(ecoPythonLock))
	require.Contains(t, plan.intelEcosystems(), "PyPI")
}

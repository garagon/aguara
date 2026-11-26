package commands

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// A manifest that declares dependencies without a lockfile is dependency
// evidence the audit never evaluated: an install would resolve versions
// nothing checked. Triage reviews it, the handoff and action plan withhold
// installation, and the verdict and exit code stay as they were because
// no finding was produced.
func TestAuditReviewsManifestsWithoutLockfile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cases := map[string]struct{ file, content, ecosystem string }{
		"npm":       {"package.json", `{"dependencies":{"express":"^4.18.0"}}`, "npm"},
		"pyproject": {"pyproject.toml", "[project]\nname = \"x\"\ndependencies = [\"requests>=2\"]\n", "PyPI"},
		"setup.py":  {"setup.py", "from setuptools import setup\nsetup(install_requires=['requests'])\n", "PyPI"},
		"setup.cfg": {"setup.cfg", "[options]\ninstall_requires =\n    requests\n", "PyPI"},
		"Pipfile":   {"Pipfile", "[packages]\nrequests = \"*\"\n", "PyPI"},
		"pip-tools": {"requirements.in", "requests\n", "PyPI"},
		"cargo":     {"Cargo.toml", "[package]\nname = \"x\"\n[dependencies]\nserde = \"1\"\n", "crates.io"},
		"bundler":   {"Gemfile", "source \"https://rubygems.org\"\ngem \"rails\"\n", "RubyGems"},
		"composer":  {"composer.json", `{"require":{"monolog/monolog":"^3.0"}}`, "Packagist"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := projectWith(t, map[string]string{tc.file: tc.content})
			result := auditToFile(t, dir)
			require.Equal(t, "pass", result.Verdict.Status)
			require.False(t, result.Verdict.ThresholdExceeded)
			require.Len(t, result.Coverage.UnsupportedEvidence, 1)
			u := result.Coverage.UnsupportedEvidence[0]
			require.Equal(t, filepath.Join(dir, tc.file), u.Path)
			require.Equal(t, tc.ecosystem, u.Ecosystem)
			require.Equal(t, "manifest_without_lockfile", u.Reason)
			require.Equal(t, "review", result.Triage.Decision)
			requireTriageReason(t, result.Triage, "manifest_without_lockfile")
			require.Contains(t, result.Triage.RecommendedNextSteps[0], "Generate or commit a lockfile for "+tc.file)
			require.Equal(t, "review_only", result.Handoff.Status)
			require.Contains(t, result.Handoff.Summary, "could not evaluate")
			require.False(t, result.Plan.CanInstallDependencies)
			require.False(t, result.Plan.CanExecuteProjectCode)
			require.Contains(t, result.Plan.Priority, "manifest_without_lockfile")
		})
	}
}

// The same manifests beside an evaluated lockfile, or without
// dependencies, change nothing.
func TestAuditProceedsForManifestsWithLockfiles(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for name, files := range map[string]map[string]string{
		"npm": {"package.json": `{"dependencies":{"express":"^4.18.0"}}`,
			"package-lock.json": `{"lockfileVersion":3,"packages":{"":{"name":"x"},"node_modules/express":{"version":"4.18.2"}}}`},
		"uv": {"pyproject.toml": "[project]\nname = \"x\"\ndependencies = [\"requests\"]\n",
			"uv.lock": "version = 1\n\n[[package]]\nname = \"requests\"\nversion = \"2.32.3\"\nsource = { registry = \"https://pypi.org/simple\" }\n"},
		"cargo": {"Cargo.toml": "[package]\nname = \"x\"\n[dependencies]\nserde = \"1\"\n",
			"Cargo.lock": "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"},
		"composer": {"composer.json": `{"require":{"monolog/monolog":"^3.0"}}`,
			"composer.lock": `{"packages":[{"name":"monolog/monolog","version":"3.5.0"}],"packages-dev":[]}`},
		"bundler": {"Gemfile": "gem \"rack\"\n", "Gemfile.lock": "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.0.8)\n"},
		"no dependencies": {"package.json": `{"name":"x","scripts":{"build":"tsc"}}`,
			"pyproject.toml": "[build-system]\nrequires = [\"setuptools\"]\n[project]\nname = \"x\"\n"},
		"npm workspace": {"package.json": `{"private":true,"workspaces":["packages/*"]}`,
			"package-lock.json":       `{"lockfileVersion":3,"packages":{"":{"name":"root"}}}`,
			"packages/a/package.json": `{"dependencies":{"express":"^4.18.0"}}`,
			"packages/b/package.json": `{"dependencies":{"lodash":"^4.17.21"}}`},
		"cargo workspace": {"Cargo.toml": "[workspace]\nmembers = [\"crates/*\"]\n", "Cargo.lock": "version = 4\n",
			"crates/a/Cargo.toml": "[package]\nname = \"a\"\n[dependencies]\nserde = \"1\"\n"},
	} {
		t.Run(name, func(t *testing.T) {
			result := auditToFile(t, projectWith(t, files))
			require.Empty(t, result.Coverage.UnsupportedEvidence)
			require.Equal(t, "proceed", result.Triage.Decision, "%+v", result.Triage.Reasons)
			require.True(t, result.Plan.CanInstallDependencies)
		})
	}
}

// A requirements file covers a pyproject.toml only when it pins what a
// plain install of it resolves; a file that installs the project itself,
// or pins something unrelated, leaves the audit at review and says what
// is not pinned.
func TestAuditRequirementsCoverageOfPythonManifests(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	const project = "[project]\nname = \"app\"\ndependencies = [\"requests>=2\"]\n"
	for name, tc := range map[string]struct {
		requirements, decision, message string
	}{
		"editable project":   {"-e .\n", "review", "requirements.txt installs a local project"},
		"bare dot":           {".\n", "review", "requirements.txt installs a local project"},
		"unrelated pin only": {"black==24.4.2\n", "review", "requirements.txt does not pin requests with == or ==="},
		"compiled":           {"certifi==2024.2.2\nrequests==2.32.3\nurllib3==2.2.1\n", "proceed", ""},
	} {
		t.Run(name, func(t *testing.T) {
			dir := projectWith(t, map[string]string{"pyproject.toml": project, "requirements.txt": tc.requirements})
			result := auditToFile(t, dir)
			require.Equal(t, tc.decision, result.Triage.Decision, "%+v", result.Triage.Reasons)
			require.Equal(t, tc.decision == "proceed", result.Plan.CanInstallDependencies)
			if tc.message == "" {
				require.Empty(t, result.Coverage.UnsupportedEvidence)
				return
			}
			requireTriageReason(t, result.Triage, "manifest_without_lockfile")
			for _, r := range result.Triage.Reasons {
				if r.Kind == "manifest_without_lockfile" {
					require.Contains(t, r.Message, "pyproject.toml (PyPI; "+tc.message)
				}
			}
			require.Len(t, result.Coverage.UnsupportedEvidence, 1)
			require.Equal(t, filepath.Join(dir, "requirements.txt"), result.Coverage.UnsupportedEvidence[0].RequirementsFile)
		})
	}
}

// NuGet central package management: versionless references read their
// versions from Directory.Packages.props, and floating or range versions
// review like unpinned Python requirements.
func TestAuditNuGetCentralPackageManagement(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	props := `<Project><ItemGroup><PackageVersion Include="8y234rtv8yvf" Version="1.0.0" /><PackageVersion Include="Clean.Pkg" Version="2.*" /></ItemGroup></Project>`
	dir := projectWith(t, map[string]string{
		"Directory.Packages.props": props,
		"src/App/App.csproj":       `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="8y234rtv8yvf" /></ItemGroup></Project>`,
	})
	result := auditToFile(t, dir)
	require.Equal(t, "stop", result.Triage.Decision, "a central version pinning a compromised release is a finding")
	require.Equal(t, 1, result.Verdict.CheckCriticals)

	dir = projectWith(t, map[string]string{
		"Directory.Packages.props": props,
		"src/App/App.csproj":       `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Clean.Pkg" /></ItemGroup></Project>`,
	})
	result = auditToFile(t, dir)
	require.Equal(t, "review", result.Triage.Decision)
	requireTriageReason(t, result.Triage, "unpinned_dependency_evidence")
	require.Contains(t, result.Triage.RecommendedNextSteps[0], "packages.lock.json")
	require.False(t, result.Plan.CanInstallDependencies)
	require.Equal(t, "pass", result.Verdict.Status)
}

// A pinned requirements file that pins nothing the manifest declares, or
// that the manifest does not name as its dependency source, leaves the
// manifest's install unchecked.
func TestAuditPythonManifestNeedsItsOwnPins(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for name, tc := range map[string]struct {
		files    map[string]string
		decision string
	}{
		"setup.py literal list": {map[string]string{
			"setup.py": "from setuptools import setup\nsetup(name='demo', install_requires=['requests>=2'])\n", "requirements.txt": "black==24.1.0\n"}, "review"},
		"dynamic dependencies": {map[string]string{
			"pyproject.toml": "[project]\nname = \"demo\"\nversion = \"1\"\ndynamic = [\"dependencies\"]\n", "requirements.txt": "black==24.1.0\n"}, "review"},
		"keyword unpacking": {map[string]string{
			"setup.py": "import json\nfrom setuptools import setup\nsetup(**json.load(open('meta.json')))\n", "requirements.txt": "black==24.1.0\n"}, "review"},
		"dynamic dependencies from the pinned file": {map[string]string{
			"pyproject.toml":   "[project]\nname = \"demo\"\nversion = \"1\"\ndynamic = [\"dependencies\"]\n[tool.setuptools.dynamic]\ndependencies = {file = [\"requirements.txt\"]}\n",
			"requirements.txt": "requests==2.31.0\n"}, "proceed"},
		"setup.py literal list pinned": {map[string]string{
			"setup.py": "from setuptools import setup\nsetup(name='demo', install_requires=['requests>=2'])\n", "requirements.txt": "requests==2.31.0\n"}, "proceed"},
	} {
		t.Run(name, func(t *testing.T) {
			result := auditToFile(t, projectWith(t, tc.files))
			require.Equal(t, tc.decision, result.Triage.Decision, "%+v", result.Triage.Reasons)
			if tc.decision == "review" {
				requireTriageReason(t, result.Triage, "manifest_without_lockfile")
			}
		})
	}
}

// The gaps that let NuGet references pass unchecked: a compromised
// version in a conditional PackageVersion that a later one shadows, a
// version from a property the project does not define, and central
// versions applied although the project turns central management off.
func TestAuditNuGetCentralVersionGaps(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := projectWith(t, map[string]string{
		"Directory.Packages.props": `<Project><ItemGroup>
<PackageVersion Include="8y234rtv8yvf" Version="1.0.0" Condition="'$(TargetFramework)' == 'net48'" />
<PackageVersion Include="8y234rtv8yvf" Version="2.0.0" />
</ItemGroup></Project>`,
		"src/App/App.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="8y234rtv8yvf" /></ItemGroup></Project>`,
	})
	result := auditToFile(t, dir)
	require.Equal(t, "stop", result.Triage.Decision, "every central version declared for the package is checked")

	for name, project := range map[string]string{
		"undefined property": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Clean.Pkg" Version="$(CleanPkgVersion)" /></ItemGroup></Project>`,
		"central management off": `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><ManagePackageVersionsCentrally>false</ManagePackageVersionsCentrally></PropertyGroup>
<ItemGroup><PackageReference Include="Clean.Pkg" /></ItemGroup></Project>`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := projectWith(t, map[string]string{
				"Directory.Packages.props": `<Project><ItemGroup><PackageVersion Include="Clean.Pkg" Version="2.0.0" /></ItemGroup></Project>`,
				"src/App/App.csproj":       project,
			})
			result := auditToFile(t, dir)
			require.Equal(t, "review", result.Triage.Decision)
			requireTriageReason(t, result.Triage, "unpinned_dependency_evidence")
		})
	}
}

// A workspace without a lockfile is listed once, at its root, with the
// number of manifests below it that a root lockfile would cover. A
// separate project with its own lockfile below the root is covered by it.
func TestAuditListsWorkspaceRootOnce(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := projectWith(t, map[string]string{
		"package.json":             `{"private":true,"workspaces":["packages/*"]}`,
		"packages/a/package.json":  `{"dependencies":{"express":"^4.18.0"}}`,
		"packages/b/package.json":  `{"dependencies":{"lodash":"^4.17.21"}}`,
		"packages/c/package.json":  `{"name":"c"}`,
		"tools/other/package.json": `{"dependencies":{"chalk":"^5"}}`,
		"tools/own/package.json":   `{"dependencies":{"chalk":"^5"}}`,
		"tools/own/yarn.lock":      "# yarn lockfile v1\n",
	})
	result := auditToFile(t, dir)
	require.Equal(t, []string{"package.json"}, unsupportedRelPaths(t, dir, result))
	require.Equal(t, 4, result.Coverage.UnsupportedEvidence[0].NestedManifests)
	requireTriageReason(t, result.Triage, "manifest_without_lockfile")
	require.Contains(t, result.Triage.RecommendedNextSteps[0], "package.json (npm workspace root, 4 more manifests below it)")
}

// An exact pin in a manifest without a lockfile installs that release, so
// a pin of a compromised release is a real finding.
func TestAuditStopsOnCompromisedManifestPin(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for name, files := range map[string]map[string]string{
		"package.json":   {"package.json": "{\n  \"dependencies\": {\n    \"event-stream\": \"3.3.6\"\n  }\n}\n"},
		"pyproject.toml": {"pyproject.toml": "[project]\nname = \"x\"\ndependencies = [\n  \"litellm==1.82.7\",\n]\n"},
		"conda":          {"environment.yml": "name: x\ndependencies:\n  - python=3.11\n  - pip:\n    - litellm==1.82.7\n"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := projectWith(t, files)
			result := auditToFile(t, dir)
			require.Equal(t, "stop", result.Triage.Decision)
			require.Equal(t, 1, result.Verdict.CheckCriticals)
			require.Len(t, result.Check.Findings, 1)
			f := result.Check.Findings[0]
			require.NotEmpty(t, f.AdvisoryIDs)
			for _, id := range f.AdvisoryIDs {
				require.Contains(t, f.Title, id)
			}
			require.Equal(t, 1, result.Coverage.UnsupportedEvidence[0].ExactPinsChecked)
			require.Equal(t, "blocked", result.Handoff.Status)
			require.False(t, result.Plan.CanInstallDependencies)
		})
	}
}

// check reports manifest-only projects truthfully instead of "No
// dependency files found", and exits 0 because nothing was found.
func TestCheckTerminalNamesManifestsWithoutLockfile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := projectWith(t, map[string]string{"package.json": `{"dependencies":{"express":"^4.18.0"}}`})
	out := readReport(t, "check", dir)
	require.Contains(t, out, "Not evaluated: package.json (dependency manifest without a lockfile; the versions an install would resolve were not checked)")
	require.Contains(t, out, "No resolved versions were checked")
	require.NotContains(t, out, "No dependency files found")

	var check struct {
		Coverage struct {
			UnsupportedEvidence []map[string]any `json:"unsupported_evidence"`
		} `json:"coverage"`
		Findings []any `json:"findings"`
	}
	require.NoError(t, json.Unmarshal(checkToFileRaw(t, dir), &check))
	require.Empty(t, check.Findings)
	require.Len(t, check.Coverage.UnsupportedEvidence, 1)
	require.Equal(t, "manifest_without_lockfile", check.Coverage.UnsupportedEvidence[0]["reason"])
	require.NotContains(t, check.Coverage.UnsupportedEvidence[0], "exact_pins_checked", "omitted when zero")

	empty := readReport(t, "check", projectWith(t, map[string]string{"README.md": "# x\n"}))
	require.Contains(t, empty, "No dependency files found")
}

func TestAuditTerminalNamesManifestsWithoutLockfile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := projectWith(t, map[string]string{"Cargo.toml": "[package]\nname = \"x\"\n[dependencies]\nserde = \"1\"\n"})
	out := readReport(t, "audit", dir)
	require.Contains(t, out, "Not evaluated: Cargo.toml (dependency manifest without a lockfile")
	require.Contains(t, out, "(coverage incomplete, see triage)")
	require.Contains(t, out, "Triage: REVIEW")
	require.Contains(t, out, "Next: Generate or commit a lockfile for Cargo.toml (crates.io), then run the audit again.")
	require.Contains(t, out, "install=no")
	require.False(t, strings.Contains(out, "✔ Verdict"))
}

package packagecheck

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/intel"
	"github.com/stretchr/testify/require"
)

func writeTree(t *testing.T, root string, files ...string) {
	t.Helper()
	for _, name := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte("x\n"), 0o644))
	}
}

func TestDiscoverUnsupportedFindsKnownDependencyFiles(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root,
		"web/deno.lock",
		"services/api/packages.config",
		"app/ios/Podfile.lock",
		"README.md",
		// Parsed formats are never unsupported.
		"package-lock.json",
		"uv.lock",
		"services/api/requirements-dev.txt",
		// Installed trees and skipped directories are not project
		// evidence; they are skipped by name, as Discover skips them.
		"node_modules/dep/deno.lock",
		".venv/lib/python3.12/site-packages/dep/paket.lock",
		"lib/site-packages/other/deno.lock",
		"vendor/x/gems.locked",
	)

	got, err := DiscoverUnsupported(root, nil)
	require.NoError(t, err)
	require.Equal(t, map[string]string{
		"web/deno.lock":                "deno.lock/npm",
		"services/api/packages.config": "packages.config/NuGet",
		"app/ios/Podfile.lock":         "Podfile.lock/CocoaPods",
	}, unsupportedByPath(t, root, got))
}

func unsupportedByPath(t *testing.T, root string, got []UnsupportedEvidence) map[string]string {
	t.Helper()
	rel := map[string]string{}
	for _, u := range got {
		r, err := filepath.Rel(root, u.Path)
		require.NoError(t, err)
		rel[filepath.ToSlash(r)] = u.Kind + "/" + u.Ecosystem
	}
	return rel
}

// A pyvenv.cfg is ordinary repository content: planting one at the root
// or beside a dependency file must not hide that file, the same rule
// Discover applies.
func TestDiscoverUnsupportedIgnoresPlantedVenvMarkers(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, "pyvenv.cfg", "deno.lock", "tools/pyvenv.cfg", "tools/gems.locked")
	got, err := DiscoverUnsupported(root, nil)
	require.NoError(t, err)
	require.Equal(t, map[string]string{
		"deno.lock":         "deno.lock/npm",
		"tools/gems.locked": "gems.locked/RubyGems",
	}, unsupportedByPath(t, root, got))
}

func TestDiscoverUnsupportedFiltersByEcosystem(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, "gems.locked", "deno.lock", "packages.config")
	got, err := DiscoverUnsupported(root, []string{intel.EcosystemNuGet})
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "packages.config", got[0].Kind)
}

func TestDiscoverUnsupportedSkipsInstalledRoots(t *testing.T) {
	for _, dir := range []string{"node_modules", "site-packages"} {
		root := filepath.Join(t.TempDir(), dir)
		writeTree(t, root, "dep/deno.lock", "dep/paket.lock")
		got, err := DiscoverUnsupported(root, nil)
		require.NoError(t, err)
		require.Empty(t, got, "%s is an installed tree, not a project", dir)
		require.NotNil(t, got)
	}
}

// Discovery reads requirements*.txt and constraints*.txt by name. pip
// files under other names install dependencies just the same, so they
// are reported when they name a requirement (pinned or a range) or an
// include: the file name must not decide the outcome. Prose .txt files
// fail to parse and are not reported, and neither are empty or
// comment-only files, nor pip files under other patterns.
func TestDiscoverUnsupportedPythonRequirementsNames(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"dev-requirements.txt":               "pytest==8.2.0\n",
		"services/api/test_requirements.txt": "coverage==7.5.1\n",
		"requirements/dev.txt":               "black==24.4.2\n",
		"requirements/prod.txt":              "-r base.txt\n",
		"tox-requirements.txt":               "pytest>=7\n",
		"requirements/notes.txt":             "Install the tools listed below before running the suite.\n",
		"docs_requirements.txt":              "# nothing yet\n",
		"dev-reqs.txt":                       "pytest==8.2.0\n", // other names are not listed
		"requirements.pip":                   "pytest==8.2.0\n",
		"requirements/requirements-ci.txt":   "ruff==0.4.4\n", // read by discovery
		"requirements.in":                    "flask==3.0.0\n",
		"pyproject.toml":                     "[project]\ndependencies = [\"flask==3.0.0\"]\n",
		"Pipfile":                            "[packages]\nflask = \"==3.0.0\"\n",
		"environment.yml":                    "dependencies:\n  - pip:\n    - flask==3.0.0\n",
	}
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}
	got, err := DiscoverUnsupported(root, nil)
	require.NoError(t, err)
	require.Equal(t, map[string]string{
		"dev-requirements.txt":               "requirements.txt/PyPI",
		"services/api/test_requirements.txt": "requirements.txt/PyPI",
		"requirements/dev.txt":               "requirements.txt/PyPI",
		"requirements/prod.txt":              "requirements.txt/PyPI",
		"tox-requirements.txt":               "requirements.txt/PyPI",
	}, unsupportedByPath(t, root, got))
}

// Every unsupported format must stay out of the parsed set. Adding a
// parser for one of them fails here until its entry is removed from
// unsupportedFormats.
func TestUnsupportedFormatsAreNotParsed(t *testing.T) {
	for _, f := range unsupportedFormats {
		t.Run(f.Dir+"/"+f.Pattern, func(t *testing.T) {
			root := t.TempDir()
			name := strings.ReplaceAll(f.Pattern, "*", "dev")
			if f.Dir != "" {
				name = f.Dir + "/" + name
			}
			path := filepath.Join(root, filepath.FromSlash(name))
			require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
			// Python entries are reported only when they name a requirement.
			require.NoError(t, os.WriteFile(path, []byte("flask==3.0.0\n"), 0o644))
			targets, err := Discover(root, nil)
			require.NoError(t, err)
			require.Empty(t, targets, "%s is parsed now: remove it from unsupportedFormats", name)
			found, err := DiscoverUnsupported(root, nil)
			require.NoError(t, err)
			require.Len(t, found, 1, "pattern %s must match %s", f.Pattern, name)
			require.Equal(t, f.Kind, found[0].Kind)
		})
	}
}

// Only the ecosystems Aguara has no intelligence for are NoIntel; every
// other listed format is unevaluated because no parser reads it.
func TestUnsupportedFormatsNoIntel(t *testing.T) {
	noIntel := map[string]bool{}
	for _, f := range unsupportedFormats {
		if (UnsupportedEvidence{Ecosystem: f.Ecosystem}).NoIntel() {
			noIntel[f.Kind] = true
		}
	}
	require.Equal(t, map[string]bool{
		"pubspec.lock": true, "Podfile.lock": true, "Package.resolved": true, "mix.lock": true,
	}, noIntel)
	require.False(t, UnsupportedEvidence{}.NoIntel(), "an unknown ecosystem is not claimed to lack intelligence")
}

func TestCoverageJSONUsesEmptyArrays(t *testing.T) {
	data, err := json.Marshal(Coverage{})
	require.NoError(t, err)
	require.JSONEq(t, `{"package_evidence":[],"unsupported_evidence":[],"unresolved_includes":[]}`, string(data))
}

func TestSummarizeEvidenceGroupsByEcosystemAndSource(t *testing.T) {
	got := SummarizeEvidence([]EcosystemResult{
		{Ecosystem: "npm", Source: "package-lock.json", Path: "a/package-lock.json", PackagesRead: 3},
		{Ecosystem: "Go", Source: "go.sum", Path: "go.sum", PackagesRead: 5},
		{Ecosystem: "npm", Source: "package-lock.json", Path: "b/package-lock.json", PackagesRead: 4},
		{Ecosystem: "npm", Source: "node_modules", Path: "node_modules", PackagesRead: 0},
		{Ecosystem: "PyPI", Source: "requirements.txt", Path: "requirements.txt", PackagesRead: 4, Unpinned: 3},
		{Ecosystem: "PyPI", Source: "requirements.txt", Path: "api/requirements.txt", PackagesRead: 2, Unpinned: 1},
	})
	require.Equal(t, []EvidenceSummary{
		{Ecosystem: "npm", Source: "package-lock.json", Targets: 2, PackagesRead: 7},
		{Ecosystem: "Go", Source: "go.sum", Targets: 1, PackagesRead: 5},
		{Ecosystem: "npm", Source: "node_modules", Targets: 1, PackagesRead: 0},
		{Ecosystem: "PyPI", Source: "requirements.txt", Targets: 2, PackagesRead: 6, Unpinned: 4},
	}, got)
	require.NotNil(t, SummarizeEvidence(nil))
}

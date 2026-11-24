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
		"uv.lock",
		"services/api/poetry.lock",
		"services/api/requirements-dev.txt",
		"web/deno.lock",
		"app/ios/Podfile.lock",
		"README.md",
		"package-lock.json", // parsed, never unsupported
		// Installed trees and skipped directories are not project evidence.
		"node_modules/dep/requirements.txt",
		".venv/pyvenv.cfg",
		".venv/lib/python3.12/site-packages/dep/requirements.txt",
		"lib/site-packages/other/poetry.lock",
		"vendor/x/uv.lock",
	)

	got, err := DiscoverUnsupported(root, nil)
	require.NoError(t, err)
	rel := map[string]string{}
	for _, u := range got {
		r, err := filepath.Rel(root, u.Path)
		require.NoError(t, err)
		rel[filepath.ToSlash(r)] = u.Kind + "/" + u.Ecosystem
	}
	require.Equal(t, map[string]string{
		"uv.lock":                           "uv.lock/PyPI",
		"services/api/poetry.lock":          "poetry.lock/PyPI",
		"services/api/requirements-dev.txt": "requirements.txt/PyPI",
		"web/deno.lock":                     "deno.lock/npm",
		"app/ios/Podfile.lock":              "Podfile.lock/CocoaPods",
	}, rel)
}

func TestDiscoverUnsupportedFiltersByEcosystem(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, "uv.lock", "deno.lock", "packages.config")
	got, err := DiscoverUnsupported(root, []string{intel.EcosystemNuGet})
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "packages.config", got[0].Kind)
}

func TestDiscoverUnsupportedSkipsInstalledRoots(t *testing.T) {
	for _, dir := range []string{"node_modules", "site-packages"} {
		root := filepath.Join(t.TempDir(), dir)
		writeTree(t, root, "dep/requirements.txt", "dep/uv.lock")
		got, err := DiscoverUnsupported(root, nil)
		require.NoError(t, err)
		require.Empty(t, got, "%s is an installed tree, not a project", dir)
		require.NotNil(t, got)
	}
}

// Every unsupported format must stay out of the parsed set. Adding a
// parser for one of them fails here until its entry is removed from
// unsupportedFormats.
func TestUnsupportedFormatsAreNotParsed(t *testing.T) {
	for _, f := range unsupportedFormats {
		t.Run(f.Pattern, func(t *testing.T) {
			root := t.TempDir()
			name := strings.ReplaceAll(f.Pattern, "*", "-dev")
			writeTree(t, root, name)
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
	require.JSONEq(t, `{"package_evidence":[],"unsupported_evidence":[]}`, string(data))
}

func TestSummarizeEvidenceGroupsByEcosystemAndSource(t *testing.T) {
	got := SummarizeEvidence([]EcosystemResult{
		{Ecosystem: "npm", Source: "package-lock.json", Path: "a/package-lock.json", PackagesRead: 3},
		{Ecosystem: "Go", Source: "go.sum", Path: "go.sum", PackagesRead: 5},
		{Ecosystem: "npm", Source: "package-lock.json", Path: "b/package-lock.json", PackagesRead: 4},
		{Ecosystem: "npm", Source: "node_modules", Path: "node_modules", PackagesRead: 0},
	})
	require.Equal(t, []EvidenceSummary{
		{Ecosystem: "npm", Source: "package-lock.json", Targets: 2, PackagesRead: 7},
		{Ecosystem: "Go", Source: "go.sum", Targets: 1, PackagesRead: 5},
		{Ecosystem: "npm", Source: "node_modules", Targets: 1, PackagesRead: 0},
	}, got)
	require.NotNil(t, SummarizeEvidence(nil))
}

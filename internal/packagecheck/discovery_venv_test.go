package packagecheck

import (
	"path/filepath"
	"sort"
	"testing"

	"github.com/garagon/aguara/internal/intel"
	"github.com/stretchr/testify/require"
)

func discoveredSources(t *testing.T, root string, ecosystems []string) []string {
	t.Helper()
	targets, err := Discover(root, ecosystems)
	require.NoError(t, err)
	var out []string
	for _, tg := range targets {
		rel, err := filepath.Rel(root, tg.Path)
		require.NoError(t, err)
		out = append(out, filepath.ToSlash(rel))
	}
	sort.Strings(out)
	return out
}

// A pyvenv.cfg file is attacker-controlled content in a scanned
// repository. It must not hide the lockfiles next to it.
func TestDiscoverWalksDirectoriesThatOnlyCarryAVenvMarker(t *testing.T) {
	root := t.TempDir()
	web := filepath.Join(root, "web")
	writeFile(t, filepath.Join(web, "pyvenv.cfg"), "home = /usr/bin\n")
	writeFile(t, filepath.Join(web, "package-lock.json"), `{"lockfileVersion":3,"packages":{"node_modules/event-stream":{"version":"3.3.6"}}}`)
	writeFile(t, filepath.Join(web, "go.sum"), "example.com/malicious-mod v1.2.3 h1:abc=\n")
	writeFile(t, filepath.Join(web, "Cargo.lock"), "[[package]]\nname = \"compromised-crate\"\nversion = \"1.2.3\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n")
	writeFile(t, filepath.Join(web, "composer.lock"), `{"packages":[{"name":"vendor/pkg","version":"1.0.0"}]}`)
	writeFile(t, filepath.Join(web, "Gemfile.lock"), "GEM\n  remote: https://rubygems.org/\n  specs:\n    rake (13.0.6)\n")
	writeFile(t, filepath.Join(web, "gradle.lockfile"), "org.example:lib:1.0.0=runtimeClasspath\n")
	writeFile(t, filepath.Join(web, "packages.lock.json"), `{"version":1,"dependencies":{"net8.0":{"Pkg":{"type":"Direct","resolved":"1.0.0"}}}}`)
	writeFile(t, filepath.Join(web, "requirements.txt"), "num2words==0.5.15\n")

	require.Equal(t, []string{
		"web/Cargo.lock", "web/Gemfile.lock", "web/composer.lock", "web/go.sum", "web/gradle.lockfile",
		"web/package-lock.json", "web/packages.lock.json", "web/requirements.txt",
	}, discoveredSources(t, root, nil))

	matcher := intel.NewMatcher(intel.Snapshot{Records: []intel.Record{
		{ID: "MAL-NPM", Ecosystem: intel.EcosystemNPM, Name: "event-stream", Kind: intel.KindMalicious, Versions: []string{"3.3.6"}},
		{ID: "MAL-GO", Ecosystem: intel.EcosystemGo, Name: "example.com/malicious-mod", Kind: intel.KindMalicious, Versions: []string{"v1.2.3"}},
		{ID: "MAL-PYPI", Ecosystem: intel.EcosystemPyPI, Name: "num2words", Kind: intel.KindMalicious, Versions: []string{"0.5.15"}},
	}})
	targets, err := Discover(root, []string{intel.EcosystemNPM, intel.EcosystemGo, intel.EcosystemPyPI})
	require.NoError(t, err)
	res, err := (&Runner{Matcher: matcher}).Run(targets)
	require.NoError(t, err)
	var ids []string
	for _, h := range res.Hits {
		ids = append(ids, h.Record.ID)
	}
	require.ElementsMatch(t, []string{"MAL-NPM", "MAL-GO", "MAL-PYPI"}, ids)
}

// A real virtual environment under another name is walked like any
// directory, but its installed packages (site-packages) are not searched
// for dependency files.
func TestDiscoverRealVirtualEnvironmentUnderAnotherName(t *testing.T) {
	root := t.TempDir()
	env := filepath.Join(root, "env")
	writeFile(t, filepath.Join(env, "pyvenv.cfg"), "home = /usr/bin\n")
	writeFile(t, filepath.Join(env, "lib", "python3.12", "site-packages", "dep", "requirements.txt"), "x==1\n")
	writeFile(t, filepath.Join(env, "lib", "python3.12", "site-packages", "dep", "package-lock.json"), `{"lockfileVersion":3,"packages":{}}`)
	writeFile(t, filepath.Join(env, "Lib", "site-packages", "dep", "uv.lock"), "version = 1\n")
	writeFile(t, filepath.Join(root, ".venv", "requirements.txt"), "x==1\n")
	writeFile(t, filepath.Join(root, "requirements.txt"), "x==1\n")
	require.Equal(t, []string{"requirements.txt"}, discoveredSources(t, root, nil))
}

// Exclusions apply below the scan root. A project that happens to live
// under a directory named site-packages or .venv is still checked; a
// scan root that is itself an installed tree reads no Python dependency
// files from the installed packages.
func TestDiscoverScanRootUnderInstallDirectoryName(t *testing.T) {
	for _, parent := range []string{"site-packages", "dist-packages", "__pypackages__", ".venv"} {
		t.Run(parent, func(t *testing.T) {
			project := filepath.Join(t.TempDir(), parent, "project")
			writeFile(t, filepath.Join(project, "requirements.txt"), "x==1\n")
			writeFile(t, filepath.Join(project, "go.sum"), "example.com/m v1.0.0 h1:abc=\n")
			require.Equal(t, []string{"go.sum", "requirements.txt"}, discoveredSources(t, project, nil))
		})
	}
	site := filepath.Join(t.TempDir(), "lib", "python3.12", "site-packages")
	writeFile(t, filepath.Join(site, "dep", "requirements.txt"), "x==1\n")
	require.Empty(t, discoveredSources(t, site, []string{intel.EcosystemPyPI}))
}

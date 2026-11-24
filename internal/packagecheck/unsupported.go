package packagecheck

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/garagon/aguara/internal/intel"
)

// unsupportedFormat is a dependency file Aguara recognizes by name but
// does not parse. Pattern is matched against the base name with
// filepath.Match.
type unsupportedFormat struct {
	Pattern   string
	Kind      string
	Ecosystem string
}

// unsupportedFormats is the single list of dependency files that are
// reported as found-but-not-evaluated. These files pin (or commonly pin)
// the packages a project installs, so a check that skips them must say
// so instead of reading as a clean result.
//
// When a parser for one of these formats is added to lockfilePickers,
// delete its entry here. TestUnsupportedFormatsAreNotParsed fails while
// a format is in both places; until then the CLI also drops any entry
// whose path discovery returned as a parsed target, so a file is never
// reported as both read and unsupported.
//
// Manifests without resolved versions (package.json without a lockfile,
// pyproject.toml, Cargo.toml, Gemfile, composer.json) are not listed:
// they do not pin what an install resolves.
var unsupportedFormats = []unsupportedFormat{
	// PyPI
	{Pattern: "uv.lock", Kind: "uv.lock", Ecosystem: intel.EcosystemPyPI},
	{Pattern: "poetry.lock", Kind: "poetry.lock", Ecosystem: intel.EcosystemPyPI},
	{Pattern: "Pipfile.lock", Kind: "Pipfile.lock", Ecosystem: intel.EcosystemPyPI},
	{Pattern: "pdm.lock", Kind: "pdm.lock", Ecosystem: intel.EcosystemPyPI},
	{Pattern: "pylock.toml", Kind: "pylock.toml", Ecosystem: intel.EcosystemPyPI},
	{Pattern: "pylock.*.toml", Kind: "pylock.toml", Ecosystem: intel.EcosystemPyPI},
	{Pattern: "requirements*.txt", Kind: "requirements.txt", Ecosystem: intel.EcosystemPyPI},
	// npm
	{Pattern: "npm-shrinkwrap.json", Kind: "npm-shrinkwrap.json", Ecosystem: intel.EcosystemNPM},
	{Pattern: "deno.lock", Kind: "deno.lock", Ecosystem: intel.EcosystemNPM},
	// RubyGems
	{Pattern: "gems.locked", Kind: "gems.locked", Ecosystem: intel.EcosystemRubyGems},
	// NuGet
	{Pattern: "packages.config", Kind: "packages.config", Ecosystem: intel.EcosystemNuGet},
	{Pattern: "paket.lock", Kind: "paket.lock", Ecosystem: intel.EcosystemNuGet},
	// Ecosystems without malicious-package intelligence in Aguara.
	{Pattern: "pubspec.lock", Kind: "pubspec.lock", Ecosystem: "Pub"},
	{Pattern: "Podfile.lock", Kind: "Podfile.lock", Ecosystem: "CocoaPods"},
	{Pattern: "Package.resolved", Kind: "Package.resolved", Ecosystem: "SwiftURL"},
	{Pattern: "mix.lock", Kind: "mix.lock", Ecosystem: "Hex"},
}

// pythonEnvDirs are installed-package trees, not project files: a
// dependency's own requirements.txt inside them says nothing about the
// project.
var pythonEnvDirs = map[string]bool{
	"site-packages": true,
	"dist-packages": true,
	"__pycache__":   true,
	".tox":          true,
	".nox":          true,
}

// DiscoverUnsupported walks root like Discover and returns the
// dependency files listed in unsupportedFormats. When ecosystems is
// non-empty only those ecosystems are reported. It skips the same
// directories as Discover, installed trees (node_modules, site-packages,
// virtual environments) and roots inside them.
func DiscoverUnsupported(root string, ecosystems []string) ([]UnsupportedEvidence, error) {
	out := []UnsupportedEvidence{}
	if hasNodeModulesAncestor(root) || isPythonEnvDir(root) {
		return out, nil
	}
	want := map[string]bool{}
	for _, eco := range ecosystems {
		want[eco] = true
	}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// Same policy as Discover: an unreadable nested directory
			// does not abort the walk.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if path != root && (defaultSkipDirs[d.Name()] || isPythonEnvDir(path)) {
				return fs.SkipDir
			}
			return nil
		}
		for _, f := range unsupportedFormats {
			if len(want) > 0 && !want[f.Ecosystem] {
				continue
			}
			if ok, _ := filepath.Match(f.Pattern, d.Name()); ok {
				out = append(out, UnsupportedEvidence{Path: path, Kind: f.Kind, Ecosystem: f.Ecosystem})
				break
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// isPythonEnvDir reports whether dir is an installed Python tree: a
// site-packages style directory or a virtual environment root.
func isPythonEnvDir(dir string) bool {
	if pythonEnvDirs[filepath.Base(filepath.Clean(dir))] {
		return true
	}
	_, err := os.Lstat(filepath.Join(dir, "pyvenv.cfg"))
	return err == nil
}

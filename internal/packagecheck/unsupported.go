package packagecheck

import (
	"io/fs"
	"path/filepath"

	"github.com/garagon/aguara/internal/intel"
)

// unsupportedFormat is a dependency file Aguara recognizes by name but
// does not parse. Pattern is matched against the base name with
// filepath.Match; when Dir is set, the file's parent directory must
// also have that name.
type unsupportedFormat struct {
	Pattern   string
	Dir       string
	Kind      string
	Ecosystem string
}

func (f unsupportedFormat) matches(path string) bool {
	if f.Dir != "" && filepath.Base(filepath.Dir(path)) != f.Dir {
		return false
	}
	ok, _ := filepath.Match(f.Pattern, filepath.Base(path))
	return ok
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
// pyproject.toml, Pipfile, requirements.in, setup.py, Cargo.toml,
// Gemfile, composer.json) are not listed: they do not pin what an
// install resolves. Neither is a conda environment.yml: the name is
// common outside conda, and its conda-channel packages have no
// intelligence here.
var unsupportedFormats = []unsupportedFormat{
	// PyPI: pip requirements files that discovery does not pick up by
	// name (it reads requirements*.txt and constraints*.txt). They are
	// reported only when no read requirements file includes them.
	{Pattern: "*-requirements*.txt", Kind: "requirements.txt", Ecosystem: intel.EcosystemPyPI},
	{Pattern: "*_requirements*.txt", Kind: "requirements.txt", Ecosystem: intel.EcosystemPyPI},
	{Pattern: "*.txt", Dir: "requirements", Kind: "requirements.txt", Ecosystem: intel.EcosystemPyPI},
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

// DiscoverUnsupported walks root like Discover and returns the
// dependency files listed in unsupportedFormats. When ecosystems is
// non-empty only those ecosystems are reported. It skips exactly the
// directories Discover skips, by name (node_modules, vendor, .venv,
// site-packages, ...), and returns nothing for a root that is itself an
// installed tree. A directory is never skipped for a marker file it
// contains: a planted pyvenv.cfg must not hide the files beside it.
func DiscoverUnsupported(root string, ecosystems []string) ([]UnsupportedEvidence, error) {
	out := []UnsupportedEvidence{}
	if hasNodeModulesAncestor(root) || isPythonInstallRoot(root) {
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
			if path != root && (defaultSkipDirs[d.Name()] || isPythonEnvironmentDir(d.Name())) {
				return fs.SkipDir
			}
			return nil
		}
		for _, f := range unsupportedFormats {
			if len(want) > 0 && !want[f.Ecosystem] {
				continue
			}
			if !f.matches(path) {
				continue
			}
			if f.Ecosystem == intel.EcosystemPyPI && (isRequirementsSource(d.Name()) || !pinsRequirements(path)) {
				// Discovery reads it by name, or it is not a pip
				// requirements file that pins anything.
				break
			}
			out = append(out, UnsupportedEvidence{Path: path, Kind: f.Kind, Ecosystem: f.Ecosystem})
			break
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// pinsRequirements reports whether path parses as a pip requirements
// file and pins at least one exact version or includes another file.
// Those are dependency evidence an install would use; a .txt that is
// prose, or a list of ranges like a manifest, is not reported.
func pinsRequirements(path string) bool {
	file, err := parseRequirementsFile(path)
	if err != nil {
		return false
	}
	for _, item := range file.items {
		if item.include != "" || (item.ref != nil && !item.ref.Unpinned) {
			return true
		}
	}
	return false
}

// isPythonInstallRoot reports a root that is itself an installed-package
// tree, by its own name only, as Discover decides it.
func isPythonInstallRoot(root string) bool {
	abs, err := filepath.Abs(root)
	return err == nil && pythonInstallDirs[filepath.Base(abs)]
}

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

// reason is the coverage reason an entry of this format carries.
func (f unsupportedFormat) reason() string {
	switch {
	case f.Ecosystem == intel.EcosystemPyPI:
		return ReasonRequirementsNameNotRead
	case intel.CanonicaliseEcosystem(f.Ecosystem) == "":
		return ReasonNoPackageIntelligence
	default:
		return ReasonFormatNotParsed
	}
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
// Manifests without resolved versions (package.json, pyproject.toml,
// Pipfile, requirements.in, setup.py, setup.cfg, Cargo.toml, Gemfile,
// composer.json) and conda environment files are handled by
// manifestSpecs: they are listed only when they declare dependencies
// that no lockfile covers.
var unsupportedFormats = []unsupportedFormat{
	// PyPI: pip requirements files that discovery does not pick up by
	// name (it reads requirements*.txt and constraints*.txt). They are
	// reported only when they parse as pip requirements and name a
	// requirement or an include, and no read requirements file includes
	// them. The content check keeps prose and word lists that fail pip's
	// grammar out; names such as prereqs.txt are not patterns here.
	{Pattern: "*requirements*.txt", Kind: "requirements.txt", Ecosystem: intel.EcosystemPyPI},
	{Pattern: "reqs*.txt", Kind: "requirements.txt", Ecosystem: intel.EcosystemPyPI},
	{Pattern: "*-reqs*.txt", Kind: "requirements.txt", Ecosystem: intel.EcosystemPyPI},
	{Pattern: "*_reqs*.txt", Kind: "requirements.txt", Ecosystem: intel.EcosystemPyPI},
	{Pattern: "*.pip", Kind: "requirements.txt", Ecosystem: intel.EcosystemPyPI},
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

// Unevaluated is what a discovery walk found besides the files it reads:
// dependency files in formats it does not read, and dependency manifests.
type Unevaluated struct {
	Unsupported []UnsupportedEvidence
	Manifests   []Manifest
}

// DiscoverUnsupported walks root like Discover and returns the
// dependency files listed in unsupportedFormats. When ecosystems is
// non-empty only those ecosystems are reported. It skips exactly the
// directories Discover skips, by name (node_modules, vendor, .venv,
// site-packages, ...), and returns nothing for a root that is itself an
// installed tree. A directory is never skipped for a marker file it
// contains: a planted pyvenv.cfg must not hide the files beside it.
func DiscoverUnsupported(root string, ecosystems []string) ([]UnsupportedEvidence, error) {
	found, err := DiscoverUnevaluated(root, ecosystems)
	if err != nil {
		return nil, err
	}
	return found.Unsupported, nil
}

// DiscoverUnevaluated is DiscoverUnsupported plus the dependency manifests
// under root (see manifestSpecs), found in the same walk. Manifests are
// read with bounded, non-executing parsers; whether a lockfile covers them
// is decided by ManifestsWithoutLockfile.
func DiscoverUnevaluated(root string, ecosystems []string) (Unevaluated, error) {
	out := Unevaluated{Unsupported: []UnsupportedEvidence{}, Manifests: []Manifest{}}
	if hasNodeModulesAncestor(root) || isPythonInstallRoot(root) {
		return out, nil
	}
	want := map[string]bool{}
	for _, eco := range ecosystems {
		want[eco] = true
	}
	parsed := 0
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
		if m, ok := readManifestAt(path, want, &parsed); ok {
			out.Manifests = append(out.Manifests, m)
			return nil
		}
		for _, f := range unsupportedFormats {
			if len(want) > 0 && !want[f.Ecosystem] {
				continue
			}
			if !f.matches(path) {
				continue
			}
			entry := UnsupportedEvidence{Path: path, Kind: f.Kind, Ecosystem: f.Ecosystem, Reason: f.reason()}
			if f.Ecosystem == intel.EcosystemPyPI {
				if isRequirementsSource(d.Name()) {
					// Discovery reads it by name.
					break
				}
				pins, ok := namesRequirements(path)
				if !ok {
					// Not a pip requirements file that names anything
					// to install.
					break
				}
				entry.pins = pins
			}
			out.Unsupported = append(out.Unsupported, entry)
			break
		}
		return nil
	})
	if err != nil {
		return Unevaluated{}, err
	}
	return out, nil
}

// namesRequirements reports whether path parses as a pip requirements
// file and names at least one requirement (pinned or a range) or
// include, and returns its exact pins. A range-only file is reported too:
// read by name, the same content would make the audit review its
// unpinned entries, so the file name must not decide the outcome. A .txt
// with a line outside the pip grammar is reported only when it also pins
// an exact version: prose under such a name is not reported, and the pins
// of a pip file with one unreadable line are still matched.
func namesRequirements(path string) ([]PackageRef, bool) {
	file, err := parseRequirementsFile(path)
	if err != nil {
		return nil, false
	}
	names := false
	var pins []PackageRef
	for _, item := range file.items {
		if item.include != "" {
			names = true
		}
		if item.ref == nil {
			continue
		}
		names = true
		if item.ref.Version != "" && !item.ref.Unpinned && len(pins) < maxManifestEntries {
			pin := *item.ref
			pin.Path, pin.Source = path, filepath.Base(path)
			pins = append(pins, pin)
		}
	}
	if file.syntax != nil {
		// A line outside the pip grammar: a text file such as prose
		// reads as words here and there, so the file counts as a pip
		// file only when it also pins an exact version.
		names = len(pins) > 0
	}
	return pins, names
}

// isPythonInstallRoot reports a root that is itself an installed-package
// tree, by its own name only, as Discover decides it.
func isPythonInstallRoot(root string) bool {
	abs, err := filepath.Abs(root)
	return err == nil && pythonInstallDirs[filepath.Base(abs)]
}

package packagecheck

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/garagon/aguara/internal/intel"
)

// Coverage reasons for UnsupportedEvidence.
const (
	// ReasonFormatNotParsed: a lockfile format Aguara does not parse.
	ReasonFormatNotParsed = "format_not_parsed"
	// ReasonNoPackageIntelligence: a file of an ecosystem Aguara has no
	// malicious-package intelligence for.
	ReasonNoPackageIntelligence = "no_package_intelligence"
	// ReasonRequirementsNameNotRead: a pip requirements file under a name
	// discovery does not read, that no read file includes.
	ReasonRequirementsNameNotRead = "requirements_name_not_read"
	// ReasonManifestWithoutLockfile: a manifest that declares dependencies
	// with no evaluated lockfile for its ecosystem in its directory or a
	// parent directory inside the checked root.
	ReasonManifestWithoutLockfile = "manifest_without_lockfile"
)

// ecosystemConda labels conda environment files. Aguara has no
// intelligence for conda channels; the file's pip list is PyPI.
const ecosystemConda = "conda"

// maxManifestsParsed bounds how many manifests one discovery reads. Any
// further manifest is still reported, as one whose dependencies are
// unknown, without being read.
const maxManifestsParsed = 10_000

// Manifest is a dependency manifest found under the checked root: a file
// that declares what to install but does not record the versions an
// install resolves.
type Manifest struct {
	Path      string
	Kind      string
	Ecosystem string
	// Declares reports at least one dependency an install would resolve
	// from a registry, or dependencies that could not be told from the
	// file (a dynamic list, a setup.py that names install_requires, a
	// file that could not be read).
	Declares bool
	// Workspace marks a workspace root whose lockfile covers its members.
	Workspace bool
	// Unreadable is set when the file could not be read or parsed.
	Unreadable bool
	// Pins are the entries that pin one exact registry release, with
	// Path and Source set to this manifest.
	Pins []PackageRef
}

// manifestSpec describes one manifest kind.
type manifestSpec struct {
	kind      string
	ecosystem string
	match     func(base, dir string) bool
	// read returns the manifest's info. ok is false when the file is not
	// a manifest of this kind after all (a YAML file named
	// environment.yml that is not a conda environment).
	read func(path string) (info manifestInfo, ok bool, err error)
	// marker reports a workspace marker that declares nothing itself
	// (pnpm-workspace.yaml).
	marker bool
}

func named(names ...string) func(base, dir string) bool {
	return func(base, _ string) bool {
		for _, n := range names {
			if base == n {
				return true
			}
		}
		return false
	}
}

// isRequirementsInName matches pip-tools input files: *requirements*.in,
// and *.in inside a requirements/ directory. MANIFEST.in and other .in
// files are not requirements.
func isRequirementsInName(base, dir string) bool {
	return strings.HasSuffix(base, ".in") && len(base) > len(".in") &&
		(strings.Contains(base, "requirements") || filepath.Base(dir) == "requirements")
}

func readWith(parse func([]byte) (manifestInfo, error), label string) func(string) (manifestInfo, bool, error) {
	return func(path string) (manifestInfo, bool, error) {
		data, err := readDependencyManifest(path, label)
		if err != nil {
			return manifestInfo{}, true, err
		}
		info, err := parse(data)
		return info, true, err
	}
}

// readDependencyManifest reads a manifest under the regular-file checks
// lockfiles use and the smaller manifest size limit.
func readDependencyManifest(path, label string) ([]byte, error) {
	f, err := openManifest(path, label)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return readBoundedManifestBytes(f, maxDependencyManifestBytes, label)
}

var manifestSpecs = []manifestSpec{
	{kind: "package.json", ecosystem: intel.EcosystemNPM, match: named("package.json"), read: readWith(parsePackageJSONManifest, "package.json")},
	{kind: "pnpm-workspace.yaml", ecosystem: intel.EcosystemNPM, match: named("pnpm-workspace.yaml"), marker: true},
	{kind: "composer.json", ecosystem: intel.EcosystemPackagist, match: named("composer.json"), read: readWith(parseComposerManifest, "composer.json")},
	{kind: "pyproject.toml", ecosystem: intel.EcosystemPyPI, match: named("pyproject.toml"), read: readWith(parsePyprojectManifest, "pyproject.toml")},
	{kind: "setup.py", ecosystem: intel.EcosystemPyPI, match: named("setup.py"), read: readWith(parseSetupPyManifest, "setup.py")},
	{kind: "setup.cfg", ecosystem: intel.EcosystemPyPI, match: named("setup.cfg"), read: readWith(parseSetupCfgManifest, "setup.cfg")},
	{kind: "Pipfile", ecosystem: intel.EcosystemPyPI, match: named("Pipfile"), read: readWith(parsePipfileManifest, "Pipfile")},
	{kind: "requirements.in", ecosystem: intel.EcosystemPyPI, match: isRequirementsInName, read: func(path string) (manifestInfo, bool, error) {
		info, err := parseRequirementsInManifest(path)
		return info, true, err
	}},
	{kind: "Cargo.toml", ecosystem: intel.EcosystemCargo, match: named("Cargo.toml"), read: readWith(parseCargoManifest, "Cargo.toml")},
	{kind: "Gemfile", ecosystem: intel.EcosystemRubyGems, match: named("Gemfile", "gems.rb"), read: readWith(parseGemfileManifest, "Gemfile")},
	{kind: "environment.yml", ecosystem: ecosystemConda, match: named("environment.yml", "environment.yaml"), read: func(path string) (manifestInfo, bool, error) {
		data, err := readDependencyManifest(path, "environment.yml")
		if err != nil {
			// Unreadable YAML under a common name is not claimed to be
			// a conda environment.
			return manifestInfo{}, false, nil
		}
		return parseCondaEnvironment(data)
	}},
}

// wantsManifestEcosystem reports whether an ecosystem filter selects a
// manifest. A conda environment is selected with PyPI: its pip list
// installs PyPI packages.
func wantsManifestEcosystem(want map[string]bool, eco string) bool {
	if len(want) == 0 || want[eco] {
		return true
	}
	return eco == ecosystemConda && want[intel.EcosystemPyPI]
}

// readManifestAt identifies and reads the manifest at path, or returns
// ok=false when the file is not a manifest. parsed counts the reads so far
// in this discovery.
func readManifestAt(path string, want map[string]bool, parsed *int) (Manifest, bool) {
	base, dir := filepath.Base(path), filepath.Dir(path)
	for _, spec := range manifestSpecs {
		if !spec.match(base, dir) || !wantsManifestEcosystem(want, spec.ecosystem) {
			continue
		}
		m := Manifest{Path: path, Kind: spec.kind, Ecosystem: spec.ecosystem}
		if spec.marker {
			m.Workspace = true
			return m, true
		}
		if *parsed >= maxManifestsParsed {
			m.Declares, m.Unreadable = true, true
			return m, spec.ecosystem != ecosystemConda
		}
		*parsed++
		info, ok, err := spec.read(path)
		if !ok {
			return Manifest{}, false
		}
		if err != nil {
			// Its dependencies are unknown, so it cannot be cleared.
			m.Declares, m.Unreadable = true, true
			return m, true
		}
		m.Declares, m.Workspace = info.declares(), info.workspace
		for _, pin := range info.pins {
			pin.Path, pin.Source = path, spec.kind
			m.Pins = append(m.Pins, pin)
		}
		return m, true
	}
	return Manifest{}, false
}

// LockfileDirs records, per ecosystem, the directories holding a
// lockfile the check evaluated or recognized.
type LockfileDirs map[string]map[string]bool

func (l LockfileDirs) add(eco, path string) {
	if l[eco] == nil {
		l[eco] = map[string]bool{}
	}
	l[eco][filepath.Clean(filepath.Dir(path))] = true
}

// lockfileSource reports whether a target records the resolved versions
// for its ecosystem's manifests. A requirements file read by discovery is
// the pinned dependency list of the Python project beside it; constraints
// files install nothing and do not count.
func lockfileSource(t Target) bool {
	switch t.Ecosystem {
	case intel.EcosystemNPM:
		switch t.Source {
		case "pnpm-lock.yaml", "package-lock.json", "yarn.lock", "bun.lock", "bun.lockb":
			return true
		}
	case intel.EcosystemPyPI:
		if isRequirementsSource(t.Source) {
			return !IsConstraintsFile(t.Path)
		}
		return contains(pythonLockfileNames, t.Source) || isPylockName(t.Source)
	case intel.EcosystemCargo:
		return t.Source == "Cargo.lock"
	case intel.EcosystemPackagist:
		return t.Source == "composer.lock"
	case intel.EcosystemRubyGems:
		return t.Source == "Gemfile.lock"
	}
	return false
}

// CoveringLockfiles collects the lockfile directories from the targets a
// check reads and from the unsupported lockfiles it found (npm-shrinkwrap,
// deno.lock, gems.locked): those are already listed as not evaluated, so
// their manifests are not listed a second time.
func CoveringLockfiles(targets []Target, unsupported []UnsupportedEvidence) LockfileDirs {
	locks := LockfileDirs{}
	for _, t := range targets {
		if lockfileSource(t) {
			locks.add(t.Ecosystem, t.Path)
		}
	}
	for _, u := range unsupported {
		if u.Reason == ReasonFormatNotParsed {
			locks.add(u.Ecosystem, u.Path)
		}
	}
	return locks
}

// ManifestsWithoutLockfile returns the manifests whose dependencies no
// lockfile covers, as coverage entries. The rule, per ecosystem:
//
//   - A manifest that declares no registry dependency changes nothing.
//   - A lockfile of the manifest's ecosystem in its directory, or in any
//     parent directory up to root, covers it. A workspace lockfile at the
//     workspace root therefore covers every member, and a lockfile at the
//     project root covers nested path dependencies and test fixtures that
//     an install from the root resolves through it.
//   - When no lockfile covers a workspace root (package.json with
//     "workspaces" or pnpm-workspace.yaml, a Cargo [workspace], a uv
//     [tool.uv.workspace]), only the workspace root is listed, with the
//     number of manifests below it (NestedManifests), and only if the
//     root or one of them declares dependencies: a lockfile generated at
//     the root covers all of them under the rule above.
//   - Every other uncovered manifest that declares dependencies is listed.
//   - A conda environment is always listed when it declares dependencies:
//     Aguara reads no conda lockfile and has no conda intelligence.
//
// Entries keep the manifests' exact pins (members' pins included) so the
// caller can match them. root must be the directory discovery walked.
func ManifestsWithoutLockfile(root string, manifests []Manifest, locks LockfileDirs) []UnsupportedEvidence {
	root = filepath.Clean(root)
	parent := func(d string) (string, bool) {
		if d == root {
			return "", false
		}
		p := filepath.Dir(d)
		if p == d {
			return "", false
		}
		return p, true
	}
	covered := func(eco, dir string) bool {
		for d, ok := dir, true; ok; d, ok = parent(d) {
			if locks[eco][d] {
				return true
			}
		}
		return false
	}
	// Workspace roots per ecosystem and directory, and the manifest that
	// stands for each (package.json before pnpm-workspace.yaml).
	type workspace struct {
		entry    *Manifest
		declares bool
		members  int
		pins     []PackageRef
	}
	roots := map[string]map[string]*workspace{}
	for i := range manifests {
		m := &manifests[i]
		if !m.Workspace {
			continue
		}
		dir := filepath.Clean(filepath.Dir(m.Path))
		if roots[m.Ecosystem] == nil {
			roots[m.Ecosystem] = map[string]*workspace{}
		}
		w := roots[m.Ecosystem][dir]
		if w == nil {
			w = &workspace{}
			roots[m.Ecosystem][dir] = w
		}
		if w.entry == nil || (w.entry.Kind == "pnpm-workspace.yaml" && m.Kind != "pnpm-workspace.yaml") {
			w.entry = m
		}
	}
	// A pnpm workspace is named by its root package.json when there is
	// one, even though pnpm-workspace.yaml is what declares it.
	for i := range manifests {
		m := &manifests[i]
		if w := roots[m.Ecosystem][filepath.Clean(filepath.Dir(m.Path))]; w != nil && w.entry.Kind == "pnpm-workspace.yaml" && m.Kind == "package.json" {
			w.entry = m
		}
	}
	nearestRoot := func(eco, dir string) (*workspace, string) {
		for d, ok := dir, true; ok; d, ok = parent(d) {
			if w := roots[eco][d]; w != nil {
				return w, d
			}
		}
		return nil, ""
	}

	var out []UnsupportedEvidence
	for i := range manifests {
		m := &manifests[i]
		dir := filepath.Clean(filepath.Dir(m.Path))
		if m.Ecosystem == ecosystemConda {
			if m.Declares {
				out = append(out, UnsupportedEvidence{Path: m.Path, Kind: m.Kind, Ecosystem: m.Ecosystem,
					Reason: ReasonNoPackageIntelligence, pins: m.Pins})
			}
			continue
		}
		if covered(m.Ecosystem, dir) {
			continue
		}
		if w, wdir := nearestRoot(m.Ecosystem, dir); w != nil {
			w.declares = w.declares || m.Declares
			w.pins = append(w.pins, m.Pins...)
			if wdir != dir {
				w.members++
			}
			continue
		}
		if m.Declares {
			out = append(out, UnsupportedEvidence{Path: m.Path, Kind: m.Kind, Ecosystem: m.Ecosystem,
				Reason: ReasonManifestWithoutLockfile, pins: m.Pins})
		}
	}
	for _, byDir := range roots {
		for _, w := range byDir {
			if !w.declares {
				continue
			}
			out = append(out, UnsupportedEvidence{Path: w.entry.Path, Kind: w.entry.Kind, Ecosystem: w.entry.Ecosystem,
				Reason: ReasonManifestWithoutLockfile, NestedManifests: w.members, pins: w.pins})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// IsManifest reports whether a coverage entry is a dependency manifest
// listed for having no evaluated lockfile.
func (u UnsupportedEvidence) IsManifest() bool {
	return u.Reason == ReasonManifestWithoutLockfile
}

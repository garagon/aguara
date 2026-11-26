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
	// DefaultDependencies and GroupDependencies are the PEP 503 names of
	// a Python manifest's registry dependencies: what a plain install
	// pulls, and the optional extras and dependency groups.
	// DependencyNamesKnown is false when the list cannot be told from the
	// file (setup.py, a dynamic list, an include, an unreadable file).
	DefaultDependencies, GroupDependencies []string
	DependencyNamesKnown                   bool
	// DependencyFiles are the requirements files the manifest names as
	// the source of dependencies its text does not list: a setuptools
	// file: directive (pyproject.toml, setup.cfg), a .txt or .in file
	// that setup.py names, or the file pip-compile writes for a
	// requirements.in. Paths are joined to the manifest's directory.
	DependencyFiles []string
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
		m.DefaultDependencies, m.GroupDependencies = info.defaultNames, info.groupNames
		m.DependencyNamesKnown = !info.unknown
		for _, f := range info.files {
			m.DependencyFiles = append(m.DependencyFiles, filepath.Join(dir, filepath.FromSlash(f)))
		}
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

// lockfileSource reports whether a target is a lockfile that records the
// resolved versions for its ecosystem's manifests. A Python requirements
// file is not one by itself: whether it stands for a manifest depends on
// what it pins (see requirementsCover).
func lockfileSource(t Target) bool {
	switch t.Ecosystem {
	case intel.EcosystemNPM:
		switch t.Source {
		case "pnpm-lock.yaml", "package-lock.json", "yarn.lock", "bun.lock", "bun.lockb":
			return true
		}
	case intel.EcosystemPyPI:
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
//   - A Python manifest not covered by a Python lockfile (uv.lock,
//     poetry.lock, pdm.lock, Pipfile.lock, pylock) can be covered by a
//     read requirements file in its directory or a parent directory, but
//     only when that file records what an install of the manifest
//     resolves (requirementsCover). Otherwise the entry names the nearest
//     such file and what it does not pin.
//
// Entries keep the manifests' exact pins (members' pins included) so the
// caller can match them. root must be the directory discovery walked.
func ManifestsWithoutLockfile(root string, manifests []Manifest, locks LockfileDirs, reqs []RequirementsEvidence) []UnsupportedEvidence {
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
	reqsByDir := map[string][]RequirementsEvidence{}
	for _, r := range reqs {
		dir := filepath.Clean(filepath.Dir(r.Path))
		reqsByDir[dir] = append(reqsByDir[dir], r)
	}
	for _, list := range reqsByDir {
		sort.Slice(list, func(i, j int) bool { return list[i].Path < list[j].Path })
	}
	// requirementsNote returns whether a requirements file in the
	// manifest's directory or a parent covers it, and otherwise what the
	// nearest one lacks.
	requirementsNote := func(m *Manifest, dir string) (bool, requirementsGap) {
		var nearest requirementsGap
		found := false
		for d, ok := dir, true; ok; d, ok = parent(d) {
			for _, r := range reqsByDir[d] {
				gap := requirementsCover(r, m)
				if gap.covered {
					return true, gap
				}
				if !found {
					nearest, found = gap, true
				}
			}
		}
		return false, nearest
	}
	entry := func(m *Manifest, gap requirementsGap) UnsupportedEvidence {
		u := UnsupportedEvidence{Path: m.Path, Kind: m.Kind, Ecosystem: m.Ecosystem, Reason: ReasonManifestWithoutLockfile, pins: m.Pins}
		if gap.file != "" {
			u.RequirementsFile = gap.file
			u.NotPinned = gap.notPinned
			u.Detail = gap.describe(root)
		}
		return u
	}

	var out []UnsupportedEvidence
	notes := map[*Manifest]requirementsGap{}
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
		if m.Ecosystem == intel.EcosystemPyPI && m.Declares {
			ok, gap := requirementsNote(m, dir)
			if ok {
				continue
			}
			notes[m] = gap
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
			out = append(out, entry(m, notes[m]))
		}
	}
	for _, byDir := range roots {
		for _, w := range byDir {
			if !w.declares {
				continue
			}
			u := entry(w.entry, notes[w.entry])
			u.NestedManifests, u.pins = w.members, w.pins
			out = append(out, u)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// requirementsGap is the result of checking one requirements file against
// one Python manifest.
type requirementsGap struct {
	covered bool
	file    string
	// local: the file installs a local project (-e, ".", a path, file:).
	local bool
	// notPinned: declared dependencies the file does not pin exactly.
	notPinned []string
	// unpinned, noPins: for a manifest whose dependency names are
	// unknown, the file has entries without one exact version, or pins
	// nothing.
	unpinned int
	noPins   bool
	// notNamed: the manifest's dependency names are unknown and the
	// manifest does not name the file as their source.
	notNamed bool
}

// maxNotPinned bounds the names an entry lists.
const maxNotPinned = 20

// requirementsCover decides whether a read requirements file (with its -r
// and -c includes) stands for a Python manifest beside it, so that
// installing from it resolves what the check read:
//
//   - The file must not install a local project (-e, ".", "./x", a local
//     archive, file:): pip would build that project from its own metadata
//     and resolve its dependencies anew.
//   - When the manifest's dependency names are known, each one it pulls
//     on a plain install (project dependencies, Poetry main
//     dependencies, Pipfile [packages], install_requires, requirements.in
//     entries) must be pinned with == or === in the file or a file it
//     includes. Extras and dependency groups are not required: pip
//     installs them only on request, and a compiled requirements file
//     normally pins the default set. When a manifest declares only
//     optional groups, those groups must be pinned instead, since they
//     are all an install of it would pull.
//   - When some names are unknown (a computed setup.py list or keyword
//     unpacking, a dynamic pyproject list, a setuptools file: directive, an
//     include in a requirements.in, an unreadable manifest), the names
//     that can be read must still be pinned, and the file covers the rest
//     only if the manifest names it as their source (DependencyFiles) and
//     it has at least one exact registry pin and no entry without one
//     exact version. A pinned file the manifest does not name says
//     nothing about what the manifest installs.
func requirementsCover(r RequirementsEvidence, m *Manifest) requirementsGap {
	gap := requirementsGap{file: r.Path}
	if r.Local {
		gap.local = true
		return gap
	}
	required := m.DefaultDependencies
	if len(required) == 0 {
		required = m.GroupDependencies
	}
	seen := map[string]bool{}
	for _, name := range required {
		if r.Pinned[name] || seen[name] {
			continue
		}
		seen[name] = true
		gap.notPinned = append(gap.notPinned, name)
	}
	sort.Strings(gap.notPinned)
	gap.covered = len(gap.notPinned) == 0
	if len(gap.notPinned) > maxNotPinned {
		gap.notPinned = gap.notPinned[:maxNotPinned]
	}
	if !m.DependencyNamesKnown {
		gap.notNamed = !m.namesDependencyFile(r.Path)
		gap.unpinned, gap.noPins = r.Unpinned, r.ExactPins == 0
		gap.covered = gap.covered && !gap.notNamed && r.Unpinned == 0 && r.ExactPins > 0
	}
	return gap
}

// namesDependencyFile reports whether the manifest names path as a source
// of its dependencies; paths compare with symlinked directories resolved.
func (m *Manifest) namesDependencyFile(path string) bool {
	want := ResolvedPath(path)
	for _, f := range m.DependencyFiles {
		if ResolvedPath(f) == want {
			return true
		}
	}
	return false
}

// describe says why the requirements file does not stand for the
// manifest, naming the file relative to root.
func (g requirementsGap) describe(root string) string {
	name := g.file
	if rel, err := filepath.Rel(root, g.file); err == nil && !strings.HasPrefix(rel, "..") {
		name = filepath.ToSlash(rel)
	}
	switch {
	case g.local:
		return name + " installs a local project (an editable or path entry), whose dependencies it does not pin"
	case len(g.notPinned) > 0:
		return name + " does not pin " + strings.Join(g.notPinned, ", ") + " with == or ==="
	case g.notNamed:
		return "the manifest's dependencies cannot all be read from it, and it does not name " + name + " as their source"
	case g.noPins:
		return name + " pins no exact version, and the manifest's dependencies cannot be read from it"
	case g.unpinned > 0:
		return name + " has entries without one exact version, and the manifest's dependencies cannot be read from it"
	}
	return ""
}

// IsManifest reports whether a coverage entry is a dependency manifest
// listed for having no evaluated lockfile.
func (u UnsupportedEvidence) IsManifest() bool {
	return u.Reason == ReasonManifestWithoutLockfile
}

package packagecheck

import (
	"fmt"
	"regexp"

	"github.com/pelletier/go-toml/v2/unstable"
)

// The four TOML lockfile formats share one shape: an array of package
// tables ([[package]] or [[packages]]) whose entries carry a name, a
// version and some description of where the distribution comes from.
// tomlLockFormat captures what differs between them; parseTOMLLock
// streams the document once and hands each completed entry to build.
//
// Only registry entries are emitted as PyPI packages. Entries from a
// VCS checkout, a local directory or file, a direct URL, an editable
// install or a workspace member have no PyPI identity: a local project
// named like a malicious PyPI package is not that package.
type tomlLockFormat struct {
	label string
	// arrayName is the array-of-tables key: "package" or "packages".
	arrayName string
	// sourceTable names the package sub-table (or inline table) that
	// describes the source, when the format has one.
	sourceTable string
	// arrayFields are package keys that must be arrays of strings.
	arrayFields []string
	// boolFields are package keys that must be booleans.
	boolFields []string
	// formatVersion is the full key path of the lockfile format
	// version, checked by checkVersion. Required when versionRequired.
	formatVersion   []string
	checkVersion    func(*unstable.Node) error
	versionRequired bool
	build           func(*tomlPackage) (*PackageRef, error)
}

// tomlPackage is one collected [[package]] entry. Values are copied out
// of the parser because its nodes are reused by the next expression.
type tomlPackage struct {
	line      int
	str       map[string]string
	arrays    map[string][]string
	bools     map[string]bool
	present   map[string]bool
	source    map[string]string
	sourceSet bool
	// sourceOther lists source members whose value is not a string.
	sourceOther map[string]bool
}

const (
	tomlSectionRoot = iota
	tomlSectionPackage
	tomlSectionSource
	tomlSectionPackageOther
	tomlSectionOther
)

func parseTOMLLock(data []byte, path string, f tomlLockFormat) ([]PackageRef, error) {
	coll := newPythonRefCollector(f.label)
	var cur *tomlPackage
	section := tomlSectionRoot
	var table []string
	versionSeen := false
	isArray := func(name string) bool { return contains(f.arrayFields, name) }
	isBool := func(name string) bool { return contains(f.boolFields, name) }

	flush := func() error {
		if cur == nil {
			return nil
		}
		p := cur
		cur = nil
		ref, err := f.build(p)
		if err != nil || ref == nil {
			return err
		}
		ref.Path = path
		ref.Source = f.label
		ref.Line = p.line
		return coll.add(*ref)
	}
	setSource := func(key string, v *unstable.Node) error {
		if _, dup := cur.source[key]; dup || cur.sourceOther[key] {
			return fmt.Errorf("parse %s: duplicate %s.%s", f.label, f.sourceTable, key)
		}
		if s, ok := tomlString(v); ok {
			cur.source[key] = s
		} else {
			cur.sourceOther[key] = true
		}
		return nil
	}

	err := walkTOML(data, f.label, func(e tomlExpr) error {
		switch e.kind {
		case unstable.Table, unstable.ArrayTable:
			table = e.keys
			if len(e.keys) == 0 || e.keys[0] != f.arrayName {
				section = tomlSectionOther
				return flush()
			}
			if len(e.keys) == 1 {
				if e.kind != unstable.ArrayTable {
					return fmt.Errorf("parse %s: %s must be an array of tables", f.label, f.arrayName)
				}
				if err := flush(); err != nil {
					return err
				}
				cur = &tomlPackage{line: e.line, str: map[string]string{}, arrays: map[string][]string{}, bools: map[string]bool{},
					present: map[string]bool{}, source: map[string]string{}, sourceOther: map[string]bool{}}
				section = tomlSectionPackage
				return nil
			}
			if cur == nil {
				return fmt.Errorf("parse %s: %s sub-table before any [[%s]] entry", f.label, f.arrayName, f.arrayName)
			}
			sub := e.keys[1]
			if sub == "name" || sub == "version" {
				return fmt.Errorf("parse %s: package %s cannot be a table", f.label, sub)
			}
			if f.sourceTable != "" && sub == f.sourceTable {
				if len(e.keys) != 2 || e.kind != unstable.Table || cur.sourceSet {
					return fmt.Errorf("parse %s: invalid %s table", f.label, f.sourceTable)
				}
				cur.sourceSet = true
				section = tomlSectionSource
				return nil
			}
			cur.present[sub] = true
			section = tomlSectionPackageOther
			return nil
		case unstable.KeyValue:
			full := append(append([]string(nil), table...), e.keys...)
			if section == tomlSectionRoot {
				full = e.keys
			}
			if f.formatVersion != nil && equalKeys(full, f.formatVersion) {
				if versionSeen {
					return fmt.Errorf("parse %s: duplicate format version", f.label)
				}
				versionSeen = true
				if err := f.checkVersion(e.value); err != nil {
					return err
				}
			}
			switch section {
			case tomlSectionRoot:
				if e.keys[0] == f.arrayName {
					return fmt.Errorf("parse %s: expected [[%s]] tables", f.label, f.arrayName)
				}
			case tomlSectionSource:
				if len(e.keys) != 1 {
					return fmt.Errorf("parse %s: invalid %s key", f.label, f.sourceTable)
				}
				return setSource(e.keys[0], e.value)
			case tomlSectionPackage:
				return collectTOMLPackageKey(f, cur, e, isArray, isBool, setSource)
			}
			return nil
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := flush(); err != nil {
		return nil, err
	}
	if f.versionRequired && !versionSeen {
		return nil, fmt.Errorf("parse %s: missing lockfile format version", f.label)
	}
	return coll.refs, nil
}

func collectTOMLPackageKey(f tomlLockFormat, cur *tomlPackage, e tomlExpr, isArray, isBool func(string) bool, setSource func(string, *unstable.Node) error) error {
	key := e.keys[0]
	if len(e.keys) > 1 {
		switch {
		case key == "name" || key == "version":
			return fmt.Errorf("parse %s: package %s cannot be a table", f.label, key)
		case f.sourceTable != "" && key == f.sourceTable:
			if len(e.keys) != 2 {
				return fmt.Errorf("parse %s: invalid %s key", f.label, f.sourceTable)
			}
			cur.sourceSet = true
			return setSource(e.keys[1], e.value)
		}
		cur.present[key] = true
		return nil
	}
	if cur.present[key] {
		return fmt.Errorf("parse %s: duplicate package key %s", f.label, key)
	}
	cur.present[key] = true
	switch {
	case key == "name" || key == "version":
		s, ok := tomlString(e.value)
		if !ok {
			return fmt.Errorf("parse %s: package %s must be a string", f.label, key)
		}
		cur.str[key] = s
	case f.sourceTable != "" && key == f.sourceTable:
		members, ok := tomlInlineTable(e.value)
		if !ok || cur.sourceSet {
			return fmt.Errorf("parse %s: package %s must be one inline table", f.label, key)
		}
		cur.sourceSet = true
		for k, v := range members {
			if err := setSource(k, v); err != nil {
				return err
			}
		}
	case isArray(key):
		values, ok := tomlStringArray(e.value)
		if !ok {
			return fmt.Errorf("parse %s: package %s must be an array of strings", f.label, key)
		}
		cur.arrays[key] = values
	case isBool(key):
		if e.value == nil || e.value.Kind != unstable.Bool {
			return fmt.Errorf("parse %s: package %s must be a boolean", f.label, key)
		}
		cur.bools[key] = string(e.value.Data) == "true"
	default:
		if s, ok := tomlString(e.value); ok {
			cur.str[key] = s
		}
	}
	return nil
}

func equalKeys(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func requireName(label string, p *tomlPackage) (string, error) {
	name := p.str["name"]
	if name == "" {
		return "", fmt.Errorf("parse %s: package entry without a name", label)
	}
	return name, nil
}

func requireRegistryVersion(label, name string, p *tomlPackage) (string, error) {
	version := p.str["version"]
	if version == "" {
		return "", fmt.Errorf("parse %s: registry package %q has no version", label, name)
	}
	return version, nil
}

// --- uv.lock ---------------------------------------------------------

// uvSourceKinds are the source kinds uv records in `source = { ... }`.
// Only registry sources (an index URL, or a local find-links directory
// used as an index) carry a PyPI name and version.
var uvSourceKinds = []string{"registry", "git", "url", "path", "directory", "editable", "virtual"}

var uvLockFormat = tomlLockFormat{
	label:           "uv.lock",
	arrayName:       "package",
	sourceTable:     "source",
	formatVersion:   []string{"version"},
	versionRequired: true,
	checkVersion: func(n *unstable.Node) error {
		if n == nil || n.Kind != unstable.Integer || string(n.Data) != "1" {
			return fmt.Errorf("parse uv.lock: unsupported lockfile version (this release reads version 1)")
		}
		return nil
	},
	build: func(p *tomlPackage) (*PackageRef, error) {
		const label = "uv.lock"
		name, err := requireName(label, p)
		if err != nil {
			return nil, err
		}
		if !p.sourceSet {
			return nil, fmt.Errorf("parse %s: package %q has no source", label, name)
		}
		var kind string
		for _, k := range uvSourceKinds {
			if _, ok := p.source[k]; ok || p.sourceOther[k] {
				if kind != "" {
					return nil, fmt.Errorf("parse %s: package %q has more than one source", label, name)
				}
				kind = k
			}
		}
		if kind == "" {
			return nil, fmt.Errorf("parse %s: package %q has an unsupported source", label, name)
		}
		if kind != "registry" {
			return nil, nil
		}
		if p.source["registry"] == "" {
			return nil, fmt.Errorf("parse %s: package %q has an invalid registry source", label, name)
		}
		version, err := requireRegistryVersion(label, name, p)
		if err != nil {
			return nil, err
		}
		return &PackageRef{Name: name, Version: version}, nil
	},
}

// ParseUVLock reads uv.lock (lockfile version 1) and returns the
// registry packages it pins. Git, URL, path, directory, editable and
// virtual (workspace) entries are skipped. uv does not record dependency
// groups per package, so refs carry no Group. No uv execution, no
// network.
func ParseUVLock(target Target) ([]PackageRef, error) {
	data, err := readManifest(target.Path, "uv.lock")
	if err != nil {
		return nil, fmt.Errorf("read uv.lock: %w", err)
	}
	return parseTOMLLock(data, target.Path, uvLockFormat)
}

// --- poetry.lock -----------------------------------------------------

var poetryLockFormat = tomlLockFormat{
	label:         "poetry.lock",
	arrayName:     "package",
	sourceTable:   "source",
	arrayFields:   []string{"groups"},
	formatVersion: []string{"metadata", "lock-version"},
	checkVersion: func(n *unstable.Node) error {
		v, ok := tomlString(n)
		if major, okMajor := lockVersionMajor(v); !ok || !okMajor || major < 1 || major > 2 {
			return fmt.Errorf("parse poetry.lock: unsupported lock-version (this release reads 1.x and 2.x)")
		}
		return nil
	},
	build: func(p *tomlPackage) (*PackageRef, error) {
		const label = "poetry.lock"
		name, err := requireName(label, p)
		if err != nil {
			return nil, err
		}
		if p.sourceSet {
			if p.sourceOther["type"] {
				return nil, fmt.Errorf("parse %s: package %q source type must be a string", label, name)
			}
			switch p.source["type"] {
			case "legacy":
				// An explicit or supplemental package index.
			case "git", "directory", "file", "url":
				return nil, nil
			default:
				return nil, fmt.Errorf("parse %s: package %q has an unsupported source type", label, name)
			}
		}
		version, err := requireRegistryVersion(label, name, p)
		if err != nil {
			return nil, err
		}
		groups := p.arrays["groups"]
		if len(groups) == 0 && p.str["category"] != "" {
			groups = []string{p.str["category"]}
		}
		return &PackageRef{Name: name, Version: version, Group: groupLabel(groups, "main")}, nil
	},
}

// ParsePoetryLock reads poetry.lock (lock-version 1.x and 2.x) and
// returns the packages Poetry resolved from a package index: PyPI or an
// explicit `legacy` source. Git, directory, file and URL sources are
// skipped. Group comes from `groups` (lock-version 2.1) or `category`
// (earlier versions); main dependencies carry no Group. No Poetry
// execution, no network.
func ParsePoetryLock(target Target) ([]PackageRef, error) {
	data, err := readManifest(target.Path, "poetry.lock")
	if err != nil {
		return nil, fmt.Errorf("read poetry.lock: %w", err)
	}
	return parseTOMLLock(data, target.Path, poetryLockFormat)
}

// --- pdm.lock --------------------------------------------------------

// pdmNonRegistryKeys mark entries PDM resolved from a VCS checkout, a
// local path or a direct URL rather than from an index.
var pdmNonRegistryKeys = []string{"git", "hg", "svn", "bzr", "path", "url"}

var pdmLockFormat = tomlLockFormat{
	label:         "pdm.lock",
	arrayName:     "package",
	arrayFields:   []string{"groups"},
	boolFields:    []string{"editable"},
	formatVersion: []string{"metadata", "lock_version"},
	checkVersion: func(n *unstable.Node) error {
		v, ok := tomlString(n)
		if major, okMajor := lockVersionMajor(v); !ok || !okMajor || major < 3 || major > 4 {
			return fmt.Errorf("parse pdm.lock: unsupported lock_version (this release reads 3.x and 4.x)")
		}
		return nil
	},
	build: func(p *tomlPackage) (*PackageRef, error) {
		const label = "pdm.lock"
		name, err := requireName(label, p)
		if err != nil {
			return nil, err
		}
		for _, k := range pdmNonRegistryKeys {
			if p.present[k] {
				return nil, nil
			}
		}
		if p.bools["editable"] {
			return nil, nil
		}
		version, err := requireRegistryVersion(label, name, p)
		if err != nil {
			return nil, err
		}
		return &PackageRef{Name: name, Version: version, Group: groupLabel(p.arrays["groups"], "default")}, nil
	},
}

// ParsePDMLock reads pdm.lock (lock_version 3.x and 4.x) and returns the
// packages PDM resolved from an index. Entries with a VCS, path or URL
// key, and editable entries, are skipped. Group comes from `groups`;
// the default group carries no Group. No PDM execution, no network.
func ParsePDMLock(target Target) ([]PackageRef, error) {
	data, err := readManifest(target.Path, "pdm.lock")
	if err != nil {
		return nil, fmt.Errorf("read pdm.lock: %w", err)
	}
	return parseTOMLLock(data, target.Path, pdmLockFormat)
}

// --- pylock.toml (PEP 751) -------------------------------------------

// pylockName matches the file names PEP 751 allows: pylock.toml and
// pylock.<name>.toml where <name> contains no dot.
var pylockName = regexp.MustCompile(`^pylock(\.[^.]+)?\.toml$`)

func isPylockName(base string) bool { return pylockName.MatchString(base) }

// pylockDirectSources are the PEP 751 source keys that mean "installed
// from a direct URL reference", not from an index.
var pylockDirectSources = []string{"vcs", "directory", "archive"}

var pylockFormat = tomlLockFormat{
	label:           "pylock.toml",
	arrayName:       "packages",
	formatVersion:   []string{"lock-version"},
	versionRequired: true,
	checkVersion: func(n *unstable.Node) error {
		v, ok := tomlString(n)
		// PEP 751: a tool that does not support the major version MUST
		// raise an error.
		if major, okMajor := lockVersionMajor(v); !ok || !okMajor || major != 1 {
			return fmt.Errorf("parse pylock.toml: unsupported lock-version (this release reads 1.x)")
		}
		return nil
	},
	build: func(p *tomlPackage) (*PackageRef, error) {
		name, err := requireName("pylock.toml", p)
		if err != nil {
			return nil, err
		}
		for _, k := range pylockDirectSources {
			if p.present[k] {
				return nil, nil
			}
		}
		// PEP 751 lets an index package omit its version. Record it as
		// present but unpinned instead of guessing from file names.
		if p.str["version"] == "" {
			return &PackageRef{Name: name, Unpinned: true}, nil
		}
		return &PackageRef{Name: name, Version: p.str["version"]}, nil
	},
}

// ParsePylock reads a PEP 751 lock file (pylock.toml or
// pylock.<name>.toml, lock-version 1.x) and returns its index packages.
// Packages with a vcs, directory or archive source are skipped. A
// package without a version is returned as unpinned. No network.
func ParsePylock(target Target) ([]PackageRef, error) {
	data, err := readManifest(target.Path, "pylock.toml")
	if err != nil {
		return nil, fmt.Errorf("read pylock.toml: %w", err)
	}
	refs, err := parseTOMLLock(data, target.Path, pylockFormat)
	if err != nil {
		return nil, err
	}
	if base := target.Source; base != "" && base != "pylock.toml" {
		for i := range refs {
			refs[i].Source = base
		}
	}
	return refs, nil
}

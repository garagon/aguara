package packagecheck

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/garagon/aguara/internal/intel"
	"github.com/pelletier/go-toml/v2/unstable"
	"gopkg.in/yaml.v3"
)

// Dependency manifests are read only as far as needed to tell whether
// they declare dependencies an install would resolve from a registry,
// whether they are a workspace root, and which entries pin one exact
// release. Nothing is executed: setup.py and Gemfile are Ruby and Python
// programs, so they get a textual check, never evaluation.
const (
	// maxDependencyManifestBytes bounds one manifest read. Real
	// manifests are a few kilobytes; a larger file is reported as not
	// evaluated instead of being read.
	maxDependencyManifestBytes int64 = 4 << 20
	// maxManifestLineBytes bounds one line of a line-oriented manifest.
	maxManifestLineBytes = 1 << 20
	// maxCondaYAMLNodes bounds the YAML nodes walked in one conda
	// environment file; anchors are not expanded.
	maxCondaYAMLNodes = 200_000
)

// manifestInfo is what a bounded read of a dependency manifest reports.
type manifestInfo struct {
	// deps counts the registry dependencies the manifest declares.
	deps int
	// unknown is set when the manifest's dependencies cannot be told from
	// its text (a dynamic pyproject dependency list, a setuptools file:
	// directive): it is treated as declaring dependencies.
	unknown bool
	// workspace marks a workspace root (npm, Yarn and Bun "workspaces",
	// a Cargo [workspace] table, a uv [tool.uv.workspace] table).
	workspace bool
	// pins are the entries that name one exact registry release.
	pins []PackageRef
	// defaultNames and groupNames are the PEP 503 names of the registry
	// dependencies the manifest declares, split into what a plain
	// install pulls (project dependencies, Poetry main dependencies,
	// Pipfile [packages], install_requires, requirements.in entries) and
	// optional sets (extras, dependency groups, dev dependencies). Only
	// Python manifests use them.
	defaultNames, groupNames []string
	// files are the requirements files, relative to the manifest, that
	// it names as the source of dependencies it does not list itself
	// (a setuptools file: directive, a file setup.py reads, the file
	// pip-compile writes for a requirements.in).
	files []string
}

func (m manifestInfo) declares() bool { return m.deps > 0 || m.unknown }

// addDep counts one registry dependency; group is "" for a dependency a
// plain install pulls.
func (m *manifestInfo) addDep(name, group string) error {
	if m.deps >= maxLockfileEntries {
		return fmt.Errorf("more than %d dependencies", maxLockfileEntries)
	}
	m.deps++
	if name = intel.PEP503Normalize(strings.TrimSpace(name)); name != "" {
		if group == "" {
			m.defaultNames = append(m.defaultNames, name)
		} else {
			m.groupNames = append(m.groupNames, name)
		}
	}
	return nil
}

func (m *manifestInfo) addPin(ref PackageRef) {
	if len(m.pins) < maxLockfileEntries {
		m.pins = append(m.pins, ref)
	}
}

func sortedRawKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// --- npm: package.json -----------------------------------------------

// npmDependencySections are the package.json fields an install resolves.
// npm 7 and later and pnpm install peerDependencies too.
var npmDependencySections = []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"}

// npmNonRegistryPrefixes mark specs that do not resolve from the npm
// registry: local paths, links, workspace protocols, Git hosts and URLs.
var npmNonRegistryPrefixes = []string{
	"file:", "link:", "workspace:", "portal:", "patch:", "exec:",
	"git:", "git+", "github:", "gist:", "gitlab:", "bitbucket:", "http:", "https:", "ssh:",
}

// npmExactVersion is a version npm's semver accepts as one exact version
// in loose mode (node-semver LOOSEPLAIN, which npm-package-arg uses): an
// optional "v", "=" or whitespace prefix, a full MAJOR.MINOR.PATCH whose
// numbers may carry leading zeros, an optional pre-release whose hyphen
// may be omitted, and build metadata, which the registry drops.
var npmExactVersion = regexp.MustCompile(`^[=v\s]*([0-9]+)\.([0-9]+)\.([0-9]+)(?:-?([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)

// npmExactPin returns the version an exact npm spec selects, spelled as
// node-semver formats it ("03.3.6" is 3.3.6, "1.2.3beta" is 1.2.3-beta),
// or ok=false for a range, tag or invalid spec.
func npmExactPin(spec string) (string, bool) {
	m := npmExactVersion.FindStringSubmatch(strings.TrimSpace(spec))
	if m == nil {
		return "", false
	}
	parts := make([]string, 3)
	for i, p := range m[1:4] {
		n, err := strconv.ParseUint(p, 10, 53)
		if err != nil {
			return "", false
		}
		parts[i] = strconv.FormatUint(n, 10)
	}
	v := strings.Join(parts, ".")
	if m[4] != "" {
		v += "-" + m[4]
	}
	return v, true
}

// npmRegistryDependency resolves a package.json entry to the registry
// package it installs and its spec, following an `npm:` alias. ok is
// false for local, Git, URL and workspace specs.
func npmRegistryDependency(name, spec string) (pkg, rangeSpec string, ok bool) {
	spec = strings.TrimSpace(spec)
	if rest, isAlias := strings.CutPrefix(spec, "npm:"); isAlias {
		at := strings.LastIndexByte(rest, '@')
		if at <= 0 {
			pkg, rangeSpec = rest, ""
		} else {
			pkg, rangeSpec = rest[:at], rest[at+1:]
		}
		canonical, valid := validNPMName(pkg)
		return canonical, rangeSpec, valid
	}
	for _, p := range npmNonRegistryPrefixes {
		if strings.HasPrefix(spec, p) {
			return "", "", false
		}
	}
	// "owner/repo" is GitHub shorthand and "./dir" a path; a range or a
	// tag never contains a slash.
	if strings.ContainsAny(spec, `/\`) {
		return "", "", false
	}
	canonical, valid := validNPMName(name)
	return canonical, spec, valid
}

func parsePackageJSONManifest(data []byte) (manifestInfo, error) {
	var info manifestInfo
	var top map[string]json.RawMessage
	if err := json.Unmarshal(bytes.TrimPrefix(data, []byte(utf8BOM)), &top); err != nil {
		return info, fmt.Errorf("invalid JSON")
	}
	if raw, ok := top["workspaces"]; ok && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		info.workspace = true
	}
	for _, section := range npmDependencySections {
		var deps map[string]json.RawMessage
		if raw, ok := top[section]; !ok || json.Unmarshal(raw, &deps) != nil {
			continue
		}
		for _, name := range sortedRawKeys(deps) {
			var spec string
			if json.Unmarshal(deps[name], &spec) != nil {
				continue
			}
			pkg, rangeSpec, ok := npmRegistryDependency(name, spec)
			if !ok {
				continue
			}
			if err := info.addDep("", ""); err != nil {
				return info, err
			}
			if v, ok := npmExactPin(rangeSpec); ok {
				info.addPin(PackageRef{Ecosystem: intel.EcosystemNPM, Name: pkg, Version: v, Group: groupForNPMSection(section)})
			}
		}
	}
	return info, nil
}

func groupForNPMSection(section string) string {
	switch section {
	case "devDependencies":
		return "dev"
	case "optionalDependencies":
		return "optional"
	case "peerDependencies":
		return "peer"
	default:
		return ""
	}
}

// --- Packagist: composer.json ----------------------------------------

// composerExactConstraint is a Composer constraint that selects one
// version: a classical version, optionally after "=" or "==", with an
// optional stability suffix (Composer "Versions and constraints", exact
// version constraint). Ranges, wildcards, "|" and "," never match.
var composerExactConstraint = regexp.MustCompile(`(?i)^(?:==?\s*)?(v?[0-9]{1,5}(?:\.[0-9]+){0,3}(?:[._-]?(?:stable|beta|b|RC|alpha|a|patch|pl|p)(?:[.-]?[0-9]+)*)?(?:[.-]?dev)?)$`)

func parseComposerManifest(data []byte) (manifestInfo, error) {
	var info manifestInfo
	var top map[string]json.RawMessage
	if err := json.Unmarshal(bytes.TrimPrefix(data, []byte(utf8BOM)), &top); err != nil {
		return info, fmt.Errorf("invalid JSON")
	}
	for _, section := range []string{"require", "require-dev"} {
		var deps map[string]json.RawMessage
		if raw, ok := top[section]; !ok || json.Unmarshal(raw, &deps) != nil {
			continue
		}
		for _, name := range sortedRawKeys(deps) {
			// Packages are vendor/name; names without a slash are
			// platform requirements (php, ext-*, lib-*, composer-*).
			if !strings.Contains(name, "/") {
				continue
			}
			if err := info.addDep(name, ""); err != nil {
				return info, err
			}
			var constraint string
			if json.Unmarshal(deps[name], &constraint) != nil {
				continue
			}
			// A stability flag ("1.2.3@beta") does not change the version.
			constraint, _, _ = strings.Cut(strings.TrimSpace(constraint), "@")
			if m := composerExactConstraint.FindStringSubmatch(strings.TrimSpace(constraint)); m != nil {
				group := ""
				if section == "require-dev" {
					group = "dev"
				}
				info.addPin(PackageRef{Ecosystem: intel.EcosystemPackagist, Name: strings.ToLower(name), Version: m[1], Group: group})
			}
		}
	}
	return info, nil
}

// --- PyPI: PEP 508 strings shared by pyproject, setup.cfg, conda -------

// addPEP508 records one PEP 508 dependency string. Direct references with
// no PyPI identity are not registry dependencies; a string that does not
// parse still declares a dependency whose version is unknown.
func (m *manifestInfo) addPEP508(s string, line int, group string) error {
	ref, err := parseNamedRequirement(strings.TrimSpace(s))
	if err != nil {
		m.unknown = true
		// Keep an exact pin the string still starts with for matching.
		if ref = salvageExactPin(s); ref == nil {
			return nil
		}
	}
	if ref == nil {
		return nil
	}
	if err := m.addDep(ref.Name, group); err != nil {
		return err
	}
	if ref.Version != "" {
		ref.Line = line
		ref.Group = group
		m.addPin(*ref)
	}
	return nil
}

// pipSpecifierPin reports the version a Pipfile or Poetry specifier pins
// exactly ("==1.0"), with arbitrary set for "===". "*" and ranges pin
// nothing.
func pipSpecifierPin(spec string) (version string, arbitrary, ok bool) {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "*" {
		return "", false, false
	}
	v, pinned, arb, err := parseVersionSpecifier(spec)
	if err != nil || !pinned {
		return "", false, false
	}
	return v, arb, true
}

// --- TOML manifests: pyproject.toml, Pipfile, Cargo.toml ---------------

// tomlManifestDep collects one table-shaped dependency: the attributes
// a later expression can still add ([dependencies.foo] then version =).
type tomlManifestDep struct {
	name    string
	line    int
	group   string
	version string
	// hasVersion is set when version was a string.
	hasVersion bool
	// nonRegistry marks a path, Git, URL or file source.
	nonRegistry bool
	// otherRegistry marks a Cargo registry other than crates.io.
	otherRegistry bool
	// inherited marks a Cargo `workspace = true` dependency.
	inherited bool
	// pkg is a Cargo `package = "real-name"` rename.
	pkg string
	// multiple marks a Poetry multiple-constraints list.
	multiple bool
}

// tomlDepCollector keeps table-shaped dependencies in first-seen order.
type tomlDepCollector struct {
	order []string
	deps  map[string]*tomlManifestDep
}

func newTOMLDepCollector() *tomlDepCollector {
	return &tomlDepCollector{deps: map[string]*tomlManifestDep{}}
}

func (c *tomlDepCollector) get(key, name string, line int, group string) (*tomlManifestDep, error) {
	if d, ok := c.deps[key]; ok {
		return d, nil
	}
	if len(c.order) >= maxLockfileEntries {
		return nil, fmt.Errorf("more than %d dependencies", maxLockfileEntries)
	}
	d := &tomlManifestDep{name: name, line: line, group: group}
	c.deps[key] = d
	c.order = append(c.order, key)
	return d, nil
}

// setAttr records one attribute of a table-shaped dependency.
func (d *tomlManifestDep) setAttr(attr string, value *unstable.Node) {
	switch attr {
	case "version":
		if s, ok := tomlString(value); ok {
			d.version, d.hasVersion = s, true
		}
	case "path", "git", "url", "file", "editable":
		d.nonRegistry = true
	case "registry", "registry-index":
		d.otherRegistry = true
	case "workspace":
		if value != nil && value.Kind == unstable.Bool && string(value.Data) == "true" {
			d.inherited = true
		}
	case "package":
		if s, ok := tomlString(value); ok {
			d.pkg = s
		}
	}
}

// setValue records a dependency written as `name = <value>`.
func (d *tomlManifestDep) setValue(value *unstable.Node) {
	switch {
	case value == nil:
	case value.Kind == unstable.String:
		d.version, d.hasVersion = string(value.Data), true
	case value.Kind == unstable.InlineTable:
		members, ok := tomlInlineTable(value)
		if !ok {
			return
		}
		for _, k := range sortedNodeKeys(members) {
			d.setAttr(k, members[k])
		}
	case value.Kind == unstable.Array:
		d.multiple = true
	}
}

func sortedNodeKeys(m map[string]*unstable.Node) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// walkTOMLManifest streams a TOML manifest and calls visit with the full
// key path of every key/value pair (table header plus key) and with each
// table header (value nil).
//
// An inline table is visited as its members, so `dependencies = {a = "1"}`
// under [tool.poetry] reads like a [tool.poetry.dependencies] table and
// `optional-dependencies = {docs = [...]}` under [project] like
// [project.optional-dependencies]. Nesting stays within the key-part
// bound of the parser.
func walkTOMLManifest(data []byte, label string, visit func(full []string, value *unstable.Node, line int, header bool) error) error {
	var table []string
	var expand func(full []string, value *unstable.Node, line int) error
	expand = func(full []string, value *unstable.Node, line int) error {
		if value == nil || value.Kind != unstable.InlineTable {
			return visit(full, value, line, false)
		}
		if len(full) >= maxTOMLKeyParts {
			return fmt.Errorf("parse %s: key has more than %d parts", label, maxTOMLKeyParts)
		}
		members, ok := tomlInlineTable(value)
		if !ok {
			return nil
		}
		for _, k := range sortedNodeKeys(members) {
			if err := expand(append(append([]string(nil), full...), k), members[k], line); err != nil {
				return err
			}
		}
		return nil
	}
	return walkTOML(data, label, func(e tomlExpr) error {
		if e.kind == unstable.Table || e.kind == unstable.ArrayTable {
			table = append([]string(nil), e.keys...)
			return visit(table, nil, e.line, true)
		}
		full := append(append([]string(nil), table...), e.keys...)
		return expand(full, e.value, e.line)
	})
}

func hasPrefixKeys(full []string, prefix ...string) bool {
	if len(full) < len(prefix) {
		return false
	}
	for i, p := range prefix {
		if full[i] != p {
			return false
		}
	}
	return true
}

// forEachTOMLString calls fn for each string element of an array, with
// the element's line when the parser records its offset.
func forEachTOMLString(n *unstable.Node, lines *lineCounter, fallback int, fn func(s string, line int) error) error {
	if n == nil || n.Kind != unstable.Array {
		return nil
	}
	it := n.Children()
	for it.Next() {
		el := it.Node()
		if el.Kind != unstable.String {
			continue
		}
		line := fallback
		if el.Raw.Length > 0 {
			if l := lines.at(int(el.Raw.Offset)); l > 0 {
				line = l
			}
		}
		if err := fn(string(el.Data), line); err != nil {
			return err
		}
	}
	return nil
}

func parsePyprojectManifest(data []byte) (manifestInfo, error) {
	var info manifestInfo
	poetry := newTOMLDepCollector()
	lines := &lineCounter{data: data, line: 1}
	err := walkTOMLManifest(data, "pyproject.toml", func(full []string, value *unstable.Node, line int, header bool) error {
		if hasPrefixKeys(full, "tool", "uv", "workspace") {
			info.workspace = true
		}
		if header {
			return nil
		}
		switch {
		case len(full) == 2 && full[0] == "project" && full[1] == "dependencies":
			return forEachTOMLString(value, lines, line, func(s string, l int) error { return info.addPEP508(s, l, "") })
		case len(full) == 5 && hasPrefixKeys(full, "tool", "setuptools", "dynamic", "dependencies") && full[4] == "file":
			// setuptools reads the dynamic dependency list from these
			// files (a string or a list of strings).
			if value != nil && value.Kind == unstable.String {
				info.files = append(info.files, string(value.Data))
				return nil
			}
			return forEachTOMLString(value, lines, line, func(s string, _ int) error {
				if len(info.files) < 100 {
					info.files = append(info.files, s)
				}
				return nil
			})
		case len(full) == 2 && full[0] == "project" && full[1] == "dynamic":
			_ = forEachTOMLString(value, lines, line, func(s string, _ int) error {
				if s == "dependencies" || s == "optional-dependencies" {
					info.unknown = true
				}
				return nil
			})
		case len(full) == 3 && full[0] == "project" && full[1] == "optional-dependencies":
			return forEachTOMLString(value, lines, line, func(s string, l int) error { return info.addPEP508(s, l, full[2]) })
		case len(full) == 2 && full[0] == "dependency-groups":
			return forEachTOMLString(value, lines, line, func(s string, l int) error { return info.addPEP508(s, l, full[1]) })
		case len(full) == 4 && hasPrefixKeys(full, "tool", "pdm", "dev-dependencies"):
			return forEachTOMLString(value, lines, line, func(s string, l int) error { return info.addPEP508(s, l, full[3]) })
		case len(full) == 3 && hasPrefixKeys(full, "tool", "uv", "dev-dependencies"):
			return forEachTOMLString(value, lines, line, func(s string, l int) error { return info.addPEP508(s, l, "dev") })
		case len(full) == 5 && hasPrefixKeys(full, "tool", "hatch", "envs") && (full[4] == "dependencies" || full[4] == "extra-dependencies"):
			// Hatch environments install these into their own
			// environment, not on a plain install of the project.
			return forEachTOMLString(value, lines, line, func(s string, l int) error { return info.addPEP508(s, l, "hatch-"+full[3]) })
		}
		// Poetry: [tool.poetry.dependencies], [tool.poetry.dev-dependencies]
		// and [tool.poetry.group.<name>.dependencies], with each entry
		// either `name = value` or a [<table>.<name>] sub-table.
		var depTable []string
		group := ""
		switch {
		case hasPrefixKeys(full, "tool", "poetry", "dependencies"):
			depTable = full[:3]
		case hasPrefixKeys(full, "tool", "poetry", "dev-dependencies"):
			depTable, group = full[:3], "dev"
		case len(full) >= 5 && hasPrefixKeys(full, "tool", "poetry", "group") && full[4] == "dependencies":
			depTable, group = full[:5], full[3]
		default:
			return nil
		}
		rest := full[len(depTable):]
		if len(rest) == 0 || strings.EqualFold(rest[0], "python") {
			return nil
		}
		d, err := poetry.get(strings.Join(depTable, "\x00")+"\x00"+rest[0], rest[0], line, group)
		if err != nil {
			return err
		}
		if len(rest) == 1 {
			d.setValue(value)
		} else if len(rest) == 2 {
			d.setAttr(rest[1], value)
		}
		return nil
	})
	if err != nil {
		return info, err
	}
	for _, key := range poetry.order {
		d := poetry.deps[key]
		if d.nonRegistry {
			continue
		}
		if err := info.addDep(d.name, d.group); err != nil {
			return info, err
		}
		if d.multiple || !d.hasVersion {
			continue
		}
		// Poetry reads a bare version ("1.2.3") as an exact requirement.
		spec := strings.TrimSpace(d.version)
		if spec != "" && spec[0] >= '0' && spec[0] <= '9' {
			spec = "==" + spec
		}
		if v, arb, ok := pipSpecifierPin(spec); ok {
			info.addPin(PackageRef{Ecosystem: intel.EcosystemPyPI, Name: d.name, Version: v, ArbitraryEquality: arb, Line: d.line, Group: d.group})
		}
	}
	return info, nil
}

// pipfileReservedTables are Pipfile tables that are not package
// categories; every other top-level table lists packages.
var pipfileReservedTables = map[string]bool{"source": true, "requires": true, "pipenv": true, "scripts": true}

func parsePipfileManifest(data []byte) (manifestInfo, error) {
	var info manifestInfo
	deps := newTOMLDepCollector()
	err := walkTOMLManifest(data, "Pipfile", func(full []string, value *unstable.Node, line int, header bool) error {
		if header || len(full) < 2 || pipfileReservedTables[full[0]] {
			return nil
		}
		group := ""
		if full[0] != "packages" {
			group = full[0]
		}
		d, err := deps.get(full[0]+"\x00"+full[1], full[1], line, group)
		if err != nil {
			return err
		}
		if len(full) == 2 {
			d.setValue(value)
		} else if len(full) == 3 {
			d.setAttr(full[2], value)
		}
		return nil
	})
	if err != nil {
		return info, err
	}
	for _, key := range deps.order {
		d := deps.deps[key]
		if d.nonRegistry {
			continue
		}
		if err := info.addDep(d.name, d.group); err != nil {
			return info, err
		}
		if !d.hasVersion {
			continue
		}
		if v, arb, ok := pipSpecifierPin(d.version); ok {
			info.addPin(PackageRef{Ecosystem: intel.EcosystemPyPI, Name: d.name, Version: v, ArbitraryEquality: arb, Line: d.line, Group: d.group})
		}
	}
	return info, nil
}

// cargoExactRequirement is a Cargo version requirement that selects one
// version: "=" with all three components (Cargo "Specifying
// dependencies", comparison requirements; "=1.2" is a range). A
// requirement with build metadata is left alone.
var cargoExactRequirement = regexp.MustCompile(`^=\s*((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)$`)

// cargoDependencyTable reports whether a table path is a dependency
// table and returns its length: [dependencies], [dev-dependencies],
// [build-dependencies] (and the older underscore spellings), the same
// under [target.<cfg>], and [workspace.dependencies].
func cargoDependencyTable(full []string) int {
	isDeps := func(s string) bool {
		switch s {
		case "dependencies", "dev-dependencies", "build-dependencies", "dev_dependencies", "build_dependencies":
			return true
		}
		return false
	}
	switch {
	case len(full) >= 1 && isDeps(full[0]):
		return 1
	case len(full) >= 2 && full[0] == "workspace" && full[1] == "dependencies":
		return 2
	case len(full) >= 3 && full[0] == "target" && isDeps(full[2]):
		return 3
	}
	return 0
}

func parseCargoManifest(data []byte) (manifestInfo, error) {
	var info manifestInfo
	deps := newTOMLDepCollector()
	err := walkTOMLManifest(data, "Cargo.toml", func(full []string, value *unstable.Node, line int, header bool) error {
		if len(full) > 0 && full[0] == "workspace" {
			info.workspace = true
		}
		n := cargoDependencyTable(full)
		if n == 0 || len(full) == n {
			return nil
		}
		rest := full[n:]
		group := ""
		if strings.HasPrefix(full[n-1], "dev") {
			group = "dev"
		} else if strings.HasPrefix(full[n-1], "build") {
			group = "build"
		}
		d, err := deps.get(strings.Join(full[:n], "\x00")+"\x00"+rest[0], rest[0], line, group)
		if err != nil {
			return err
		}
		switch {
		case header:
		case len(rest) == 1:
			d.setValue(value)
		case len(rest) == 2:
			d.setAttr(rest[1], value)
		}
		return nil
	})
	if err != nil {
		return info, err
	}
	for _, key := range deps.order {
		d := deps.deps[key]
		if d.nonRegistry {
			continue
		}
		if err := info.addDep("", ""); err != nil {
			return info, err
		}
		if d.otherRegistry || d.inherited || !d.hasVersion {
			continue
		}
		if m := cargoExactRequirement.FindStringSubmatch(strings.TrimSpace(d.version)); m != nil {
			name := d.name
			if d.pkg != "" {
				name = d.pkg
			}
			info.addPin(PackageRef{Ecosystem: intel.EcosystemCargo, Name: name, Version: m[1], Line: d.line, Group: d.group})
		}
	}
	return info, nil
}

// --- line-oriented manifests: setup.py, setup.cfg, Gemfile -------------

// forEachManifestLine calls fn for every line of data with its 1-based
// number, bounding the line length.
func forEachManifestLine(data []byte, label string, fn func(line int, text string) error) error {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), maxManifestLineBytes)
	n := 0
	for sc.Scan() {
		n++
		if err := fn(n, strings.TrimSuffix(sc.Text(), "\r")); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read %s: %w", label, err)
	}
	return nil
}

// parseSetupPyManifest never runs setup.py. setup() receives its
// dependencies through the install_requires and extras_require keywords,
// so a file whose code never passes them, and never unpacks keyword
// arguments into a setup() call, declares none through setup.py (a shim
// whose dependencies live in setup.cfg or pyproject.toml is covered by
// those files). Literal lists given to those keywords, directly or
// through a name bound only to literal lists, are read like any other
// manifest's (see scanSetupPy). Any other value, or keyword unpacking
// into a setup() call (which may pass a computed dict or a JSON file),
// leaves the dependency names unknown; the .txt and .in files the
// script names are recorded as the files it may read them from.
func parseSetupPyManifest(data []byte) (manifestInfo, error) {
	var info manifestInfo
	s := scanSetupPy(string(data))
	info.files = s.files
	unknownDefault, unknownGroups := false, false
	add := func(items []pyStringItem, group string) error {
		for _, it := range items {
			if err := info.addPEP508(it.value, it.line, group); err != nil {
				return err
			}
		}
		return nil
	}
	for _, v := range s.install {
		lists, dicts, ok := s.resolve(v)
		if !ok || len(dicts) > 0 {
			unknownDefault = true
			if err := add(v.listed, ""); err != nil {
				return info, err
			}
			continue
		}
		for _, l := range lists {
			if err := add(l, ""); err != nil {
				return info, err
			}
		}
	}
	for _, v := range s.extras {
		lists, dicts, ok := s.resolve(v)
		if !ok || len(lists) > 0 {
			unknownGroups = true
			continue
		}
		for _, d := range dicts {
			keys := make([]string, 0, len(d))
			for k := range d {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if err := add(d[k], k); err != nil {
					return info, err
				}
			}
		}
	}
	if s.calls && s.unpacks {
		unknownDefault = true
	}
	// Extras need not be pinned for a plain install, so unknown extras
	// matter only when nothing else is declared.
	info.unknown = info.unknown || unknownDefault || unknownGroups && len(info.defaultNames) == 0
	return info, nil
}

// parseSetupCfgManifest reads the setuptools declarative configuration:
// [options] install_requires and the [options.extras_require] entries,
// each a list of PEP 508 strings, one per line. Option names compare in
// lower case, as configparser does; full-line comments are skipped. A
// "file:" directive reads the list from another file, so the dependencies
// are unknown here.
func parseSetupCfgManifest(data []byte) (manifestInfo, error) {
	var info manifestInfo
	section, key := "", ""
	handle := func(value string, line int) error {
		value = strings.TrimSpace(value)
		if value == "" || strings.HasPrefix(value, "#") || strings.HasPrefix(value, ";") {
			return nil
		}
		if rest, ok := strings.CutPrefix(value, "file:"); ok {
			info.unknown = true
			if section == "options" {
				// install_requires = file: requirements.txt, other.txt
				for _, f := range strings.Split(rest, ",") {
					if f = strings.TrimSpace(f); f != "" && len(info.files) < 100 {
						info.files = append(info.files, f)
					}
				}
			}
			return nil
		}
		group := ""
		if section == "options.extras_require" {
			group = key
		}
		// configparser does not strip inline comments; pip-style ones are
		// common in these lists and are not part of the requirement.
		if i := strings.Index(value, " #"); i >= 0 {
			value = value[:i]
		}
		return info.addPEP508(value, line, group)
	}
	inList := func() bool {
		return (section == "options" && key == "install_requires") || (section == "options.extras_require" && key != "")
	}
	err := forEachManifestLine(data, "setup.cfg", func(line int, text string) error {
		trimmed := strings.TrimSpace(text)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			return nil
		}
		if text[0] == ' ' || text[0] == '\t' {
			// Continuation of the current option's value.
			if inList() {
				return handle(trimmed, line)
			}
			return nil
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section, key = strings.TrimSpace(trimmed[1:len(trimmed)-1]), ""
			return nil
		}
		i := strings.IndexAny(trimmed, "=:")
		if i < 0 {
			key = ""
			return nil
		}
		key = strings.ToLower(strings.TrimSpace(trimmed[:i]))
		if inList() {
			return handle(trimmed[i+1:], line)
		}
		return nil
	})
	return info, err
}

var (
	// gemfileDependency is a `gem "name"` or `gemspec` line.
	gemfileDependency = regexp.MustCompile(`^(?:gem\s*\(?\s*["'][^"']+["']|gemspec\b)`)
	// gemfileExactPin is `gem "name", "1.2.3"` or `gem "name", "= 1.2.3"`:
	// Gem::Requirement reads a bare version as "= version".
	gemfileExactPin = regexp.MustCompile(`^gem\s*\(?\s*(["'])([A-Za-z0-9][A-Za-z0-9._-]*)["']\s*,\s*(["'])\s*(?:=\s*)?([0-9]+(?:\.[0-9A-Za-z]+)*)\s*["']\s*(.*)$`)
	// gemfileOtherVersion is a further version requirement argument.
	gemfileOtherVersion = regexp.MustCompile(`^,\s*["']\s*[<>=~!0-9]`)
	// gemfileOtherSource is a Git or path option: such a gem is not
	// resolved from a gem server.
	gemfileOtherSource = regexp.MustCompile(`\b(?:git|github|gitlab|bitbucket|path)\s*:|:(?:git|github|gitlab|bitbucket|path)\s*=>`)
	// gemfileSourceBlock opens a block whose gems come from a Git
	// repository or a local path: `git "url" do`, `path "dir" do`,
	// `github "org/repo" do`.
	gemfileSourceBlock = regexp.MustCompile(`^(?:git|github|gitlab|bitbucket|path)\b.*\bdo\s*(?:\|[^|]*\|)?$`)
	// gemfileBlockOpen opens any other Ruby block or statement that a
	// later `end` closes.
	gemfileBlockOpen = regexp.MustCompile(`(?:\bdo\s*(?:\|[^|]*\|)?$)|^(?:if|unless|case|begin|while|until|for|def|class|module)\b`)
	// gemfileDynamic is a dependency the text cannot name: eval_gemfile,
	// or a gem call whose name is not a string literal.
	gemfileDynamic = regexp.MustCompile(`^eval_gemfile\b|(?:^|[\s;{(])gem\s*(?:\(\s*|\s+)[^\s"')]`)
)

// parseGemfileManifest checks a Gemfile (or gems.rb) textually: Bundler
// evaluates it as Ruby, which Aguara never does. A `gem` or `gemspec`
// line declares dependencies; `eval_gemfile` or a gem call with a
// computed name declares dependencies the text cannot name. A
// `gem "name", "version"` line with one exact version and no Git or path
// option is a pin; gems inside a `git`, `github` or `path` block come
// from that source and are neither registry dependencies nor pins.
func parseGemfileManifest(data []byte) (manifestInfo, error) {
	var info manifestInfo
	// blocks is the stack of open blocks; true marks a Git or path block.
	var blocks []bool
	inSourceBlock := func() bool {
		for _, b := range blocks {
			if b {
				return true
			}
		}
		return false
	}
	err := forEachManifestLine(data, "Gemfile", func(line int, text string) error {
		trimmed := strings.TrimSpace(text)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			return nil
		}
		code := strings.TrimSpace(strings.SplitN(trimmed, " #", 2)[0])
		switch {
		case code == "end" || strings.HasPrefix(code, "end ") || strings.HasPrefix(code, "end."):
			if len(blocks) > 0 {
				blocks = blocks[:len(blocks)-1]
			}
			return nil
		case gemfileSourceBlock.MatchString(code):
			blocks = append(blocks, true)
			return nil
		case gemfileBlockOpen.MatchString(code) && !gemfileDependency.MatchString(code):
			blocks = append(blocks, false)
		}
		if !gemfileDependency.MatchString(code) {
			if gemfileDynamic.MatchString(code) && !inSourceBlock() {
				info.unknown = true
			}
			return nil
		}
		if strings.HasPrefix(code, "gemspec") {
			info.unknown = true
			return nil
		}
		if inSourceBlock() || gemfileOtherSource.MatchString(trimmed) {
			return nil
		}
		if err := info.addDep("", ""); err != nil {
			return err
		}
		m := gemfileExactPin.FindStringSubmatch(code)
		if m == nil || gemfileOtherVersion.MatchString(strings.TrimSpace(m[5])) {
			return nil
		}
		info.addPin(PackageRef{Ecosystem: intel.EcosystemRubyGems, Name: strings.ToLower(m[2]), Version: m[4], Line: line})
		return nil
	})
	return info, err
}

// --- pip-tools input: requirements.in ---------------------------------

// parseRequirementsInManifest reads a pip-tools input file as pip
// requirements, with its -r and -c includes followed inside root as for a
// requirements file. Its names are what it and its -r includes require;
// -c constraints add none. An include that is not read (a URL, a path
// outside root, a missing file), a local project or a skipped line leaves
// the names unknown. Pins read from an include keep that file's path.
// Each include read is charged to budget (nil charges nothing); past it,
// the manifest is unreadable.
func parseRequirementsInManifest(path, root string, budget *discoveryBudget) (manifestInfo, error) {
	var info manifestInfo
	if root == "" {
		root = filepath.Dir(path)
	}
	cache := newRequirementsCache()
	if budget != nil {
		cache.charge = func(p string) bool { return budget.take(p, maxManifestBytes) }
	}
	parsed, err := parseRequirementsTarget(Target{Ecosystem: intel.EcosystemPyPI, Path: path, Source: filepath.Base(path), Root: root}, cache)
	if err != nil {
		return info, err
	}
	// pip-compile writes the compiled file beside the input, under the
	// same name with .txt for .in, pinning everything it resolved,
	// includes and local projects too.
	info.files = []string{strings.TrimSuffix(filepath.Base(path), ".in") + ".txt"}
	info.unknown = parsed.local || parsed.syntax != nil || len(parsed.unresolved) > 0
	for _, ref := range parsed.refs {
		if ref.Group == constraintGroup {
			continue
		}
		if err := info.addDep(ref.Name, ""); err != nil {
			return info, err
		}
		if ref.Version != "" && !ref.Unpinned {
			if ref.Path == path {
				// The manifest's own pins are labelled as manifest pins.
				ref.Path, ref.Source = "", ""
			}
			info.addPin(ref)
		}
	}
	return info, nil
}

// --- conda: environment.yml --------------------------------------------

// parseCondaEnvironment reads a conda environment file: a mapping whose
// `dependencies` is a sequence of conda match specs (strings) and at most
// a `pip:` mapping with a sequence of pip requirement strings. ok is false
// for a YAML file of any other shape, which is not a conda environment.
// Conda packages come from conda channels, for which Aguara has no
// intelligence; `==` pins in the pip list are PyPI pins.
func parseCondaEnvironment(data []byte) (info manifestInfo, ok bool, err error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return info, false, nil
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return info, false, nil
	}
	if countYAMLNodes(&doc, maxCondaYAMLNodes) > maxCondaYAMLNodes {
		return info, false, fmt.Errorf("more than %d YAML nodes", maxCondaYAMLNodes)
	}
	top := doc.Content[0]
	var deps *yaml.Node
	for i := 0; i+1 < len(top.Content); i += 2 {
		if top.Content[i].Kind == yaml.ScalarNode && top.Content[i].Value == "dependencies" {
			deps = top.Content[i+1]
		}
	}
	if deps == nil || deps.Kind != yaml.SequenceNode || len(deps.Content) == 0 {
		return info, false, nil
	}
	var pipItems []*yaml.Node
	for _, item := range deps.Content {
		switch {
		case item.Kind == yaml.ScalarNode && item.Tag != "!!null" && strings.TrimSpace(item.Value) != "":
		case item.Kind == yaml.MappingNode && len(item.Content) == 2 &&
			item.Content[0].Kind == yaml.ScalarNode && item.Content[0].Value == "pip" &&
			item.Content[1].Kind == yaml.SequenceNode:
			pipItems = append(pipItems, item.Content[1].Content...)
		default:
			return info, false, nil
		}
		if err := info.addDep("", "conda"); err != nil {
			return info, true, err
		}
	}
	for _, p := range pipItems {
		if p.Kind != yaml.ScalarNode {
			continue
		}
		s := strings.TrimSpace(p.Value)
		if s == "" || strings.HasPrefix(s, "-") {
			continue
		}
		if err := info.addPEP508(s, p.Line, "pip"); err != nil {
			return info, true, err
		}
	}
	return info, true, nil
}

// countYAMLNodes counts nodes up to limit+1 without following aliases.
func countYAMLNodes(n *yaml.Node, limit int) int {
	count := 0
	stack := []*yaml.Node{n}
	for len(stack) > 0 && count <= limit {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		count++
		if cur.Kind == yaml.AliasNode {
			continue
		}
		stack = append(stack, cur.Content...)
	}
	return count
}

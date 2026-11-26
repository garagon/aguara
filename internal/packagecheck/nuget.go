package packagecheck

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/garagon/aguara/internal/intel"
)

// ParseNuGet reads a NuGet manifest and returns the declared
// dependencies. Dispatches on target.Source:
//
//   - "packages.lock.json" -> parseNuGetLockfile (Direct +
//     Transitive entries; the
//     resolved-version source of truth
//     when central package management is
//     enabled)
//   - "csproj" / "fsproj" / "vbproj" -> parseNuGetProjectFile
//     (PackageReference items; the
//     version source when no lockfile
//     is in use)
//
// No external commands (`dotnet restore`, `nuget`). No network.
// obj/project.assets.json is out of scope; the build cache lives
// under skip-listed `obj/` anyway. Project.assets.json parsing
// can land in a follow-up if user demand justifies it.
func ParseNuGet(target Target) ([]PackageRef, error) {
	switch target.Source {
	case "packages.lock.json":
		return parseNuGetLockfile(target)
	case "csproj", "fsproj", "vbproj":
		return parseNuGetProjectFile(target, newRunCache())
	default:
		return nil, fmt.Errorf("packagecheck: ParseNuGet: unsupported source %q (want packages.lock.json, csproj, fsproj, or vbproj)", target.Source)
	}
}

// parseNuGetLockfile decodes packages.lock.json and emits one
// PackageRef per resolved dependency across every target
// framework. Entries without a `resolved` version are skipped:
// the `type: "Project"` marker uses that field to point at a
// sibling project rather than a registry package, and the matcher
// can only act on registry versions.
//
// Cross-framework dedup: if the same (name, version) appears
// under both net8.0 and net7.0 we emit one PackageRef — the
// matcher would otherwise count and report the same compromise
// twice when only the framework differs.
func parseNuGetLockfile(target Target) ([]PackageRef, error) {
	data, err := readNuGetManifest(target.Path)
	if err != nil {
		return nil, fmt.Errorf("open packages.lock.json: %w", err)
	}
	if err := checkJSONNodeBudget(data, "packages.lock.json"); err != nil {
		return nil, err
	}
	var lock nugetLockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse packages.lock.json: %w", err)
	}
	var refs []PackageRef
	seen := make(map[string]bool)
	for _, byPkg := range lock.Dependencies {
		for name, dep := range byPkg {
			if name == "" || dep.Resolved == "" {
				continue
			}
			key := name + "@" + dep.Resolved
			if seen[key] {
				continue
			}
			seen[key] = true
			refs = append(refs, PackageRef{
				Ecosystem: intel.EcosystemNuGet,
				Name:      name,
				Version:   dep.Resolved,
				Path:      target.Path,
				Source:    "packages.lock.json",
			})
		}
	}
	return refs, nil
}

type nugetLockfile struct {
	// Dependencies is keyed by target framework
	// (e.g. "net8.0") then by package ID.
	Dependencies map[string]map[string]nugetLockDep `json:"dependencies"`
}

type nugetLockDep struct {
	Type     string `json:"type"`
	Resolved string `json:"resolved"`
}

// parseNuGetProjectFile decodes a .csproj / .fsproj / .vbproj and
// emits one PackageRef per <PackageReference>. Both the
// attribute form (`Version="X"`) and the child-element form
// (`<Version>X</Version>`) are supported; `Update="..."` items
// (PR transitive version pins) are treated the same as
// `Include="..."` items.
//
// Property resolution covers same-file <PropertyGroup> entries:
// `$(SerilogVersion)` looks up the SerilogVersion child of any
// PropertyGroup. A property defined elsewhere (MSBuild built-ins,
// Directory.Build.props, other imports, none of which are read) leaves
// the `$(...)` placeholder, which pins nothing: the reference is
// unpinned rather than dropped.
//
// Central package management: a reference without a version takes it
// from a `VersionOverride`, or else from the `PackageVersion` items of
// the nearest Directory.Packages.props in the project's directory or a
// parent directory inside the checked root, the file MSBuild imports;
// every version those items declare for the package is returned. That
// file's `GlobalPackageReference` items apply to the project too. When
// ManagePackageVersionsCentrally is false (in the project file, or else
// in the props file), none of this applies.
//
// A version that does not select one release (a floating version such as
// "1.*", a range such as "[1.0,2.0)" or "(1.0,)", an undefined property,
// or no version found) is returned as unpinned, so the audit asks for
// review as it does for an unpinned Python requirement, unless a
// packages.lock.json beside the project records what restore resolved.
func parseNuGetProjectFile(target Target, cache *runCache) ([]PackageRef, error) {
	data, err := readNuGetManifest(target.Path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", target.Source, err)
	}
	if err := checkXMLBudget(data, target.Source); err != nil {
		return nil, err
	}
	var proj csProject
	if err := xml.Unmarshal(data, &proj); err != nil {
		return nil, fmt.Errorf("parse %s: %w", target.Source, err)
	}

	props := msbuildProperties(proj.PropertyGroups)
	central, err := centralPackageVersions(target, cache)
	if err != nil {
		return nil, err
	}
	// MSBuild evaluates the project body after the props files it
	// imports, so the project's ManagePackageVersionsCentrally wins over
	// the one Directory.Packages.props sets. Unset in both, it may come
	// from a file not read here (Directory.Build.props), so central
	// versions still apply.
	manage, set := msbuildBool(props, "ManagePackageVersionsCentrally")
	if !set {
		manage, set = central.manage, central.manageSet
	}
	centralOff := set && !manage
	if centralOff {
		central = centralVersions{}
	}
	locked := manifestCandidate(filepath.Join(filepath.Dir(target.Path), "packages.lock.json"))

	var refs []PackageRef
	seen := map[string]bool{}
	add := func(name, version string) {
		ref := PackageRef{Ecosystem: intel.EcosystemNuGet, Name: name, Path: target.Path, Source: target.Source}
		if nugetPinsOneVersion(version) {
			ref.Version = nugetExactRange(version)
		} else {
			if locked {
				// packages.lock.json records the version restore chose.
				return
			}
			ref.Unpinned, ref.Constraint = true, version
		}
		key := strings.ToLower(name) + "@" + ref.Version + "@" + ref.Constraint
		if seen[key] {
			return
		}
		seen[key] = true
		refs = append(refs, ref)
	}
	for _, ig := range proj.ItemGroups {
		for _, pr := range ig.PackageRefs {
			name := strings.TrimSpace(pr.Include)
			if name == "" {
				name = strings.TrimSpace(pr.Update)
			}
			if name == "" {
				continue
			}
			version := firstNonEmpty(pr.VersionAttr, pr.VersionChild)
			if !centralOff {
				// VersionOverride is a central-management feature.
				version = firstNonEmpty(pr.VersionOverrideAttr, pr.VersionOverrideChild, version)
			}
			if version == "" {
				// Every version the props file declares for the package
				// (conditional items can declare several) is checked.
				versions := central.versions[strings.ToLower(name)]
				if len(versions) == 0 {
					add(name, "")
				}
				for _, v := range versions {
					add(name, v)
				}
				continue
			}
			if v, ok := resolveMSBuildProperty(version, props); ok {
				version = v
			}
			// A property the project does not define stays a placeholder,
			// which pins nothing: the reference counts as unpinned.
			add(name, version)
		}
	}
	for _, g := range central.global {
		add(g.name, g.version)
	}
	return refs, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

func msbuildProperties(groups []csPropertyGroup) map[string]string {
	props := map[string]string{}
	for _, pg := range groups {
		for _, p := range pg.Properties {
			props[p.XMLName.Local] = strings.TrimSpace(p.Value)
		}
	}
	return props
}

// nugetPinsOneVersion reports a version that selects one release: a plain
// version, which restore resolves to that release when it exists, or the
// exact-match range "[1.2.3]". Floating versions and other ranges select
// whatever a feed offers at restore time.
func nugetPinsOneVersion(v string) bool {
	if v == "" || strings.Contains(v, "*") {
		return false
	}
	if strings.ContainsAny(v, "[(") || strings.HasSuffix(v, ")") || strings.HasSuffix(v, "]") {
		return nugetExactRange(v) != v
	}
	return true
}

// centralVersions is what a Directory.Packages.props declares: every
// version given for each package (lower-cased ID), in file order without
// repeats, the GlobalPackageReference items, and its
// ManagePackageVersionsCentrally setting when it has one.
type centralVersions struct {
	versions          map[string][]string
	global            []struct{ name, version string }
	manage, manageSet bool
}

// msbuildBool reads a boolean property as MSBuild compares it
// (case-insensitive "true" or "false"); set is false when the property is
// absent or has another value.
func msbuildBool(props map[string]string, name string) (value, set bool) {
	switch v := strings.TrimSpace(props[name]); {
	case strings.EqualFold(v, "true"):
		return true, true
	case strings.EqualFold(v, "false"):
		return false, true
	}
	return false, false
}

// maxNuGetPropsBytes bounds one Directory.Packages.props read, the
// dependency-manifest limit rather than the lockfile one: the file holds
// one short PackageVersion item per package (about 100 bytes), so 4 MiB
// is tens of thousands of entries, far more than a real repository
// declares. A larger file is an error, not a partial read.
const maxNuGetPropsBytes = maxDependencyManifestBytes

// nugetPropsEntry is one Directory.Packages.props parsed in a run.
type nugetPropsEntry struct {
	central centralVersions
	err     error
}

// centralPackageVersions reads the Directory.Packages.props that applies
// to the project: the first found walking up from the project's directory,
// staying inside the checked root. Its own <PropertyGroup> properties are
// resolved; imports of other props files are not followed. Each file is
// parsed once per run (cache), however many projects it applies to.
func centralPackageVersions(target Target, cache *runCache) (centralVersions, error) {
	root := target.Root
	if root == "" {
		root = filepath.Dir(target.Path)
	}
	root = filepath.Clean(root)
	for dir := filepath.Clean(filepath.Dir(target.Path)); ; {
		path := filepath.Join(dir, "Directory.Packages.props")
		if manifestCandidate(path) {
			key := ResolvedPath(path)
			e, ok := cache.nugetProps[key]
			if !ok {
				e.central, e.err = parseNuGetProps(path)
				cache.nugetProps[key] = e
			}
			return e.central, e.err
		}
		if dir == root {
			return centralVersions{}, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir || !withinDir(root, parent) {
			return centralVersions{}, nil
		}
		dir = parent
	}
}

func parseNuGetProps(path string) (centralVersions, error) {
	out := centralVersions{versions: map[string][]string{}}
	f, err := openManifest(path, "Directory.Packages.props")
	if err != nil {
		return out, fmt.Errorf("open Directory.Packages.props: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := readBoundedManifestBytes(f, maxNuGetPropsBytes, "Directory.Packages.props")
	if err != nil {
		return out, fmt.Errorf("read Directory.Packages.props: %w", err)
	}
	if err := checkXMLBudget(data, "Directory.Packages.props"); err != nil {
		return out, err
	}
	var p csProject
	if err := xml.Unmarshal(data, &p); err != nil {
		return out, fmt.Errorf("parse Directory.Packages.props: %w", err)
	}
	props := msbuildProperties(p.PropertyGroups)
	out.manage, out.manageSet = msbuildBool(props, "ManagePackageVersionsCentrally")
	resolve := func(v string) string {
		v = strings.TrimSpace(v)
		if r, ok := resolveMSBuildProperty(v, props); ok {
			return r
		}
		// An undefined property pins nothing.
		return v
	}
	seen := map[string]bool{}
	for _, ig := range p.ItemGroups {
		for _, pv := range ig.PackageVersions {
			name := strings.ToLower(strings.TrimSpace(firstNonEmpty(pv.Include, pv.Update)))
			if name == "" {
				continue
			}
			v := resolve(firstNonEmpty(pv.VersionAttr, pv.VersionChild))
			if seen[name+"\x00"+v] {
				continue
			}
			if len(seen) >= maxLockfileEntries {
				return out, errBudget("parse Directory.Packages.props: more than %d package versions", maxLockfileEntries)
			}
			seen[name+"\x00"+v] = true
			out.versions[name] = append(out.versions[name], v)
		}
		for _, g := range ig.GlobalRefs {
			if name := strings.TrimSpace(g.Include); name != "" {
				out.global = append(out.global, struct{ name, version string }{name, resolve(firstNonEmpty(g.VersionAttr, g.VersionChild))})
			}
		}
	}
	return out, nil
}

// isNuGetProjectSource reports a .NET project file source.
func isNuGetProjectSource(source string) bool {
	switch source {
	case "csproj", "fsproj", "vbproj":
		return true
	}
	return false
}

type csProject struct {
	XMLName        xml.Name          `xml:"Project"`
	PropertyGroups []csPropertyGroup `xml:"PropertyGroup"`
	ItemGroups     []csItemGroup     `xml:"ItemGroup"`
}

type csPropertyGroup struct {
	Properties []csProperty `xml:",any"`
}

type csProperty struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

type csItemGroup struct {
	PackageRefs     []csPackageRef `xml:"PackageReference"`
	PackageVersions []csPackageRef `xml:"PackageVersion"`
	GlobalRefs      []csPackageRef `xml:"GlobalPackageReference"`
}

type csPackageRef struct {
	Include              string `xml:"Include,attr"`
	Update               string `xml:"Update,attr"`
	VersionAttr          string `xml:"Version,attr"`
	VersionChild         string `xml:"Version"`
	VersionOverrideAttr  string `xml:"VersionOverride,attr"`
	VersionOverrideChild string `xml:"VersionOverride"`
}

// nugetExactRange returns the version inside NuGet's exact-match range
// notation, "[1.0]" meaning x == 1.0 (NuGet "Package versioning",
// version ranges), and any other version string unchanged. A plain
// "1.0" is a minimum version that restore resolves to the lowest
// applicable release, which the parser already reads as that version.
func nugetExactRange(v string) string {
	if len(v) < 3 || v[0] != '[' || v[len(v)-1] != ']' {
		return v
	}
	inner := strings.TrimSpace(v[1 : len(v)-1])
	if inner == "" || strings.ContainsAny(inner, ",[]()") {
		return v
	}
	return inner
}

// msbuildIsPropertyPlaceholder reports whether the version string
// is an MSBuild `$(...)` reference.
func msbuildIsPropertyPlaceholder(v string) bool {
	v = strings.TrimSpace(v)
	return strings.HasPrefix(v, "$(") && strings.HasSuffix(v, ")")
}

// resolveMSBuildProperty resolves a `$(name)` placeholder against
// the in-file PropertyGroup map. Returns ("value", true) on hit,
// ("", false) on miss or empty value. Literal versions return
// unchanged so callers do not branch on the placeholder shape.
func resolveMSBuildProperty(version string, props map[string]string) (string, bool) {
	if !msbuildIsPropertyPlaceholder(version) {
		return version, true
	}
	name := strings.TrimSuffix(strings.TrimPrefix(version, "$("), ")")
	value, ok := props[name]
	if !ok || value == "" {
		return "", false
	}
	return value, true
}

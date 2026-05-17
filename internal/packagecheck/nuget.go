package packagecheck

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"strings"

	"github.com/garagon/aguara/internal/intel"
)

// ParseNuGet reads a NuGet manifest and returns the declared
// dependencies. Dispatches on target.Source:
//
//   - "packages.lock.json" -> parseNuGetLockfile (Direct +
//                              Transitive entries; the
//                              resolved-version source of truth
//                              when central package management is
//                              enabled)
//   - "csproj" / "fsproj" / "vbproj" -> parseNuGetProjectFile
//                              (PackageReference items; the
//                              version source when no lockfile
//                              is in use)
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
		return parseNuGetProjectFile(target)
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
	data, err := os.ReadFile(target.Path)
	if err != nil {
		return nil, fmt.Errorf("open packages.lock.json: %w", err)
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
// PropertyGroup. Unresolved properties skip the reference rather
// than emit a literal `$(...)` the matcher would silently miss.
// MSBuild built-ins (TargetFramework, Configuration) and external
// imports are out of scope.
func parseNuGetProjectFile(target Target) ([]PackageRef, error) {
	data, err := os.ReadFile(target.Path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", target.Source, err)
	}
	var proj csProject
	if err := xml.Unmarshal(data, &proj); err != nil {
		return nil, fmt.Errorf("parse %s: %w", target.Source, err)
	}

	props := map[string]string{}
	for _, pg := range proj.PropertyGroups {
		for _, p := range pg.Properties {
			props[p.XMLName.Local] = strings.TrimSpace(p.Value)
		}
	}

	var refs []PackageRef
	seen := map[string]bool{}
	for _, ig := range proj.ItemGroups {
		for _, pr := range ig.PackageRefs {
			name := strings.TrimSpace(pr.Include)
			if name == "" {
				name = strings.TrimSpace(pr.Update)
			}
			if name == "" {
				continue
			}
			version := strings.TrimSpace(pr.VersionAttr)
			if version == "" {
				version = strings.TrimSpace(pr.VersionChild)
			}
			if version == "" {
				continue
			}
			if v, ok := resolveMSBuildProperty(version, props); ok {
				version = v
			} else if msbuildIsPropertyPlaceholder(version) {
				continue
			}
			key := name + "@" + version
			if seen[key] {
				continue
			}
			seen[key] = true
			refs = append(refs, PackageRef{
				Ecosystem: intel.EcosystemNuGet,
				Name:      name,
				Version:   version,
				Path:      target.Path,
				Source:    target.Source,
			})
		}
	}
	return refs, nil
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
	PackageRefs []csPackageRef `xml:"PackageReference"`
}

type csPackageRef struct {
	Include      string `xml:"Include,attr"`
	Update       string `xml:"Update,attr"`
	VersionAttr  string `xml:"Version,attr"`
	VersionChild string `xml:"Version"`
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

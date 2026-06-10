package packagecheck

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"os"
	"strings"

	"github.com/garagon/aguara/internal/intel"
)

// ParseMaven reads a Maven-family manifest and returns the declared
// `groupId:artifactId` dependencies. The parser dispatches on
// target.Source to the right reader:
//
//   - "pom.xml"          -> parsePomXML  (Maven proper)
//   - "gradle.lockfile"  -> parseGradleLockfile (both
//                            single-lockfile mode at project root
//                            and per-configuration mode under
//                            gradle/dependency-locks/)
//
// No external commands (`mvn`, `gradle`). No network. Parent POMs,
// BOMs, dependencyManagement-only declarations, profiles, and the
// full Gradle dependency graph are out of scope for PR #4; only
// explicit `<dependency>` blocks in this POM and resolved entries
// in the Gradle lockfile produce PackageRefs.
func ParseMaven(target Target) ([]PackageRef, error) {
	switch target.Source {
	case "pom.xml":
		return parsePomXML(target)
	case "gradle.lockfile":
		return parseGradleLockfile(target)
	default:
		return nil, fmt.Errorf("packagecheck: ParseMaven: unsupported source %q (want pom.xml or gradle.lockfile)", target.Source)
	}
}

// parsePomXML decodes a Maven POM and returns one PackageRef per
// `<dependency>` whose scope is included (default / compile /
// runtime) and whose `<version>` is either literal or resolvable
// against the SAME pom.xml's `<properties>` block.
//
// Property resolution covers only same-file declarations:
// `${foo.version}` looks up `<properties><foo.version>...
// </foo.version></properties>`. Maven built-ins (project.version,
// project.groupId, env.X) and external dependencyManagement
// inheritance are out of scope; unresolved placeholders skip the
// dependency rather than emit a half-formed PackageRef the
// matcher could mis-attribute.
func parsePomXML(target Target) ([]PackageRef, error) {
	data, err := os.ReadFile(target.Path)
	if err != nil {
		return nil, fmt.Errorf("open pom.xml: %w", err)
	}
	var pom pomProject
	if err := xml.Unmarshal(data, &pom); err != nil {
		return nil, fmt.Errorf("parse pom.xml: %w", err)
	}

	// Build the in-file property map. Entries arrive as a slice of
	// (tagname, chardata) pairs because the property names are
	// user-defined and not known at decode time.
	props := make(map[string]string, len(pom.Properties.Entries))
	for _, p := range pom.Properties.Entries {
		props[p.XMLName.Local] = strings.TrimSpace(p.Value)
	}

	var refs []PackageRef
	for _, dep := range pom.Dependencies.Dependency {
		if mavenScopeExcluded(dep.Scope) {
			continue
		}
		group := strings.TrimSpace(dep.GroupID)
		artifact := strings.TrimSpace(dep.ArtifactID)
		version := strings.TrimSpace(dep.Version)
		if group == "" || artifact == "" || version == "" {
			continue
		}
		if v, ok := resolveMavenProperty(version, props); ok {
			version = v
		} else if mavenIsPropertyPlaceholder(version) {
			// Unresolved ${...} placeholder. Skip rather than
			// emit a literal `${...}` string the matcher would
			// silently miss.
			continue
		}
		refs = append(refs, PackageRef{
			Ecosystem: intel.EcosystemMaven,
			Name:      group + ":" + artifact,
			Version:   version,
			Path:      target.Path,
			Source:    "pom.xml",
		})
	}
	return refs, nil
}

// pomProject mirrors the minimal subset of the Maven POM schema
// the parser consumes. The Properties slice uses xml:",any" to
// capture user-defined property names that are not known at
// decode time.
type pomProject struct {
	XMLName      xml.Name        `xml:"project"`
	Properties   pomProperties   `xml:"properties"`
	Dependencies pomDependencies `xml:"dependencies"`
}

type pomProperties struct {
	Entries []pomProperty `xml:",any"`
}

type pomProperty struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

type pomDependencies struct {
	Dependency []pomDependency `xml:"dependency"`
}

type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

// mavenExcludedScopes are POM dependency scopes excluded from the
// emitted refs. test / provided / system / import dependencies do
// not ship in the build output and should not be matched against
// runtime supply-chain advisories. The empty scope defaults to
// `compile`, which is included.
var mavenExcludedScopes = map[string]bool{
	"test":     true,
	"provided": true,
	"system":   true,
	"import":   true,
}

func mavenScopeExcluded(scope string) bool {
	return mavenExcludedScopes[strings.ToLower(strings.TrimSpace(scope))]
}

// mavenIsPropertyPlaceholder reports whether the version string is
// a `${...}` reference. Used to distinguish "literal version that
// happens to contain a `$`" from "unresolved property reference".
func mavenIsPropertyPlaceholder(v string) bool {
	v = strings.TrimSpace(v)
	return strings.HasPrefix(v, "${") && strings.HasSuffix(v, "}")
}

// resolveMavenProperty looks up a `${name}` placeholder in the
// in-file property map. Returns (value, true) on hit, ("", false)
// on miss OR when the input is not a property placeholder at all.
// Callers that already know the input is a placeholder use the
// false return as the "unresolved, skip" signal.
func resolveMavenProperty(version string, props map[string]string) (string, bool) {
	if !mavenIsPropertyPlaceholder(version) {
		// Literal version: return as-is so the caller does not
		// have to special-case the non-placeholder path.
		return version, true
	}
	name := strings.TrimSuffix(strings.TrimPrefix(version, "${"), "}")
	value, ok := props[name]
	if !ok || value == "" {
		return "", false
	}
	return value, true
}

// parseGradleLockfile reads a Gradle dependency lockfile (both the
// project-root `gradle.lockfile` and per-configuration files under
// `gradle/dependency-locks/*.lockfile`). Format per line:
//
//	group:name:version=config1,config2,...
//
// Comments (`#` prefix) and the special `empty=...` marker are
// skipped. Lines whose left side does not split cleanly into
// (group, name, version) on `:` are skipped silently — being
// conservative here trades coverage of exotic classifier shapes
// (`group:name:version:classifier`) for a zero-FP guarantee on the
// common case.
func parseGradleLockfile(target Target) ([]PackageRef, error) {
	f, err := os.Open(target.Path)
	if err != nil {
		return nil, fmt.Errorf("open gradle.lockfile: %w", err)
	}
	defer func() { _ = f.Close() }()

	var refs []PackageRef
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		left := strings.TrimSpace(line[:eq])
		if left == "" || left == "empty" {
			continue
		}
		parts := strings.Split(left, ":")
		if len(parts) != 3 {
			// Lines like `group:name:version:classifier` or
			// any other multi-colon shape land here. Skip
			// rather than risk emitting a wrong identifier.
			continue
		}
		group, name, version := parts[0], parts[1], parts[2]
		if group == "" || name == "" || version == "" {
			continue
		}
		key := group + ":" + name + ":" + version
		if seen[key] {
			continue
		}
		seen[key] = true
		refs = append(refs, PackageRef{
			Ecosystem: intel.EcosystemMaven,
			Name:      group + ":" + name,
			Version:   version,
			Path:      target.Path,
			Source:    "gradle.lockfile",
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read gradle.lockfile: %w", err)
	}
	return refs, nil
}

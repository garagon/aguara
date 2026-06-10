package packagecheck

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/garagon/aguara/internal/intel"
)

// yarnVersionRe matches the resolved-version line in a yarn classic
// (v1) entry body. The indent is anchored to EXACTLY two spaces, which
// is the block-body level yarn v1 always emits. Nested sub-block
// entries (under `dependencies:` / `optionalDependencies:`) sit at four
// spaces, so a dependency literally named `version` with an exact range
// cannot be mistaken for the block's own resolved version even when the
// block has no top-level version line. yarn v1 always quotes the value;
// yarn Berry uses `version: x.y.z` (no quotes) and is rejected before
// this runs.
var yarnVersionRe = regexp.MustCompile(`^  version\s+"([^"]+)"`)

// yarnNonRegistryProtocols are descriptor range protocols that mark a
// dependency as resolved from somewhere other than the public npm
// registry. A yarn v1 registry dependency carries a bare semver range
// (`^4.17.0`) with no protocol; any of these prefixes means the entry
// cannot be mapped with confidence to a registry (npm, name, version)
// tuple.
//
// npm: is included deliberately: in yarn v1 the `npm:` protocol only
// appears on aliased installs (`alias@npm:real@range`), where the
// directory key is the alias and the real package is embedded in the
// range. Unlike package-lock.json (which records the real package in a
// dedicated `name` field), yarn v1 offers no clean field for it, so
// the conservative choice is to skip aliases rather than sub-parse the
// range. Mapping yarn aliases to their real package is a possible
// follow-up; under-reporting beats inventing a mapping.
var yarnNonRegistryProtocols = []string{
	"npm:", "file:", "link:", "workspace:", "portal:", "patch:",
	"git+", "git:", "ssh:", "http:", "https:", "github:", "exec:",
}

// ParseYarnLock reads a yarn classic (v1) yarn.lock and returns the
// declared npm packages. It is the yarn counterpart to ParsePackageLock
// / ParsePNPMLock: a freshly cloned yarn project carries yarn.lock but
// no node_modules, and this lets
//
//	git clone <yarn repo>
//	aguara check .
//
// audit the locked dependency set before `yarn install` runs.
//
// Pure offline, line-based: yarn v1 is a bespoke format (the
// comma-separated unquoted descriptor keys are not valid YAML), so the
// parser walks blocks directly. Each block is a header line of one or
// more comma-separated descriptors ending in `:`, followed by an
// indented body carrying `version "x.y.z"`.
//
// Yarn Berry (v2+) yarn.lock is a different, YAML-shaped grammar with a
// top-level `__metadata:` block. It is detected and handled by
// parseYarnBerryLock (which reads the authoritative `resolution:`
// field); the v1 line walker below handles classic v1 only.
//
// Conservative by design, mirroring ParsePackageLock: an entry is
// emitted only when it maps with confidence to a registry tuple. Any
// descriptor with a non-registry protocol (see yarnNonRegistryProtocols,
// which includes npm: aliases), a name that is not a usable npm
// identifier, or a body without an exact resolved version is skipped.
// Results dedupe on (name, version) and come out in deterministic order.
func ParseYarnLock(target Target) ([]PackageRef, error) {
	data, err := os.ReadFile(target.Path)
	if err != nil {
		return nil, fmt.Errorf("open yarn.lock: %w", err)
	}
	// Normalize CRLF so a Windows checkout's `:\r` block headers are not
	// missed (which would skip every block and read zero packages).
	content := strings.ReplaceAll(string(data), "\r\n", "\n")

	// Berry detection. A v2+ yarn.lock has a top-level `__metadata:`
	// block header; v1 never does. Match a real header line (the whole
	// line is `__metadata:`, unindented and uncommented), not any
	// occurrence -- otherwise a v1 lockfile with `# __metadata:` in a
	// comment would route to the Berry parser and read zero packages,
	// hiding every v1 dependency. Berry uses a different (YAML-shaped)
	// grammar, so route it to the Berry parser rather than the v1 walker.
	if hasYarnBerryMetadata(content) {
		return parseYarnBerryLock(target, content)
	}

	seen := map[string]bool{}
	var refs []PackageRef
	add := func(name, version string) {
		if name == "" || version == "" {
			return
		}
		composite := name + "@" + version
		if seen[composite] {
			return
		}
		seen[composite] = true
		refs = append(refs, PackageRef{
			Ecosystem: intel.EcosystemNPM,
			Name:      name,
			Version:   version,
			Path:      target.Path,
			Source:    "yarn.lock",
		})
	}

	lines := strings.Split(content, "\n")
	i := 0
	for i < len(lines) {
		line := lines[i]
		// Skip blanks, comments, and indented lines: a block header is
		// non-indented, non-comment, and ends with ':'.
		if line == "" || line[0] == ' ' || line[0] == '\t' || strings.HasPrefix(line, "#") {
			i++
			continue
		}
		header := strings.TrimRight(line, " ")
		if !strings.HasSuffix(header, ":") {
			i++
			continue
		}

		name, registry := yarnHeaderNameAndRegistry(strings.TrimSuffix(header, ":"))

		// Scan the indented body for the first `version "..."`. yarn v1
		// emits version before the dependencies sub-block, so the first
		// match is the entry's resolved version, never a nested
		// dependency range (even one for a dependency literally named
		// "version").
		version := ""
		j := i + 1
		for j < len(lines) {
			b := lines[j]
			if b == "" || (b[0] != ' ' && b[0] != '\t') {
				break // blank line or next header ends the block
			}
			if version == "" {
				if m := yarnVersionRe.FindStringSubmatch(b); m != nil {
					version = m[1]
				}
			}
			j++
		}

		if registry && name != "" && isExactYarnVersion(version) {
			add(name, version)
		}
		i = j
	}

	sort.Slice(refs, func(i, j int) bool {
		return refs[i].Name+"@"+refs[i].Version < refs[j].Name+"@"+refs[j].Version
	})
	return refs, nil
}

// yarnHeaderNameAndRegistry parses a yarn v1 block header (the
// descriptor list, with the trailing ':' already removed) into the
// package name and whether the block resolves to a registry package.
//
// The name comes from the first descriptor. registry is false when any
// descriptor carries a non-registry protocol or fails to parse, or when
// the first descriptor's name is not a usable npm identifier — the
// conservative posture so a mixed or malformed block never emits.
func yarnHeaderNameAndRegistry(header string) (name string, registry bool) {
	descriptors := strings.Split(header, ",")
	for idx, d := range descriptors {
		n, rng, ok := yarnDescriptorParse(d)
		if !ok {
			return "", false
		}
		if !yarnRegistryRange(rng) {
			return "", false
		}
		if idx == 0 {
			canonical, valid := validNPMName(n)
			if !valid {
				return "", false
			}
			name = canonical
		}
	}
	return name, name != ""
}

// yarnDescriptorParse splits a yarn descriptor (`name@range`, optionally
// quoted) into its name and range. Scoped names keep their leading '@';
// the separating '@' is the first one after the scope. Returns ok=false
// for a descriptor with no name/range separator, an empty name, or an
// empty range (`foo@`) — all invalid shapes the conservative parser
// must skip rather than treat as a registry package.
func yarnDescriptorParse(desc string) (name, rng string, ok bool) {
	desc = strings.TrimSpace(desc)
	desc = strings.Trim(desc, `"`)
	if desc == "" {
		return "", "", false
	}
	var at int
	if strings.HasPrefix(desc, "@") {
		rel := strings.IndexByte(desc[1:], '@')
		if rel < 0 {
			return "", "", false
		}
		at = rel + 1
	} else {
		at = strings.IndexByte(desc, '@')
		if at < 0 {
			return "", "", false
		}
	}
	name, rng = desc[:at], desc[at+1:]
	if name == "" || rng == "" {
		return "", "", false
	}
	return name, rng, true
}

// yarnRegistryRange reports whether a descriptor range resolves from the
// public npm registry (a bare semver range with no protocol prefix).
func yarnRegistryRange(rng string) bool {
	for _, p := range yarnNonRegistryProtocols {
		if strings.HasPrefix(rng, p) {
			return false
		}
	}
	return true
}

// isExactYarnVersion reports whether v is a concrete resolved version
// (e.g. 4.17.21, 1.0.0-beta.1+build), not a range or protocol value.
// Guards against an accidental capture of a range from a misparsed
// body line.
func isExactYarnVersion(v string) bool {
	if v == "" {
		return false
	}
	return !strings.ContainsAny(v, " \t^~*<>=|:/")
}

// hasYarnBerryMetadata reports whether content has a top-level
// `__metadata:` block header -- the whole line (minus trailing
// whitespace) is `__metadata:`, so an indented occurrence or a comment
// like `# __metadata:` does not count.
func hasYarnBerryMetadata(content string) bool {
	for _, ln := range strings.Split(content, "\n") {
		if strings.TrimRight(ln, " \t") == "__metadata:" {
			return true
		}
	}
	return false
}

// yarnBerryResolutionRe captures the quoted resolution string in a yarn
// Berry entry body (`  resolution: "lodash@npm:4.17.21"`). The indent is
// anchored to EXACTLY two spaces -- the block-body level Berry always
// emits -- so a nested dependency literally named `resolution` (four-
// space indent under `dependencies:`) is never mistaken for the block's
// own resolution, even in a hand-edited block with reordered or missing
// top-level fields.
var yarnBerryResolutionRe = regexp.MustCompile(`^  resolution:\s+"([^"]+)"`)

// parseYarnBerryLock parses a yarn Berry (v2+) yarn.lock. Berry's body
// carries an authoritative `resolution:` field that is ALREADY
// normalized to the real package -- an npm alias descriptor
// (`my-lodash@npm:lodash@4.17.20`) resolves to `lodash@npm:4.17.20` --
// so reading resolution matches the real registry package and an alias
// cannot hide a compromised dependency behind a local name.
//
// Both the name AND version are taken from the resolution, the single
// resolved locator, so a hand-edited block whose `version:` field
// disagrees with its resolution cannot fabricate a tuple (e.g.
// resolution node-ipc@npm:9.2.3 with version: 1.0.0 must not emit
// node-ipc@1.0.0). Anything without the `npm:` protocol (workspace:,
// patch:, file:, git, exec:, virtual ...) is not a public-registry
// package and is skipped. Conservative, like the other npm parsers: an
// entry is emitted only when the name is a usable npm identifier and the
// version is an exact resolved version; results dedupe on (name,
// version) in deterministic order.
func parseYarnBerryLock(target Target, content string) ([]PackageRef, error) {
	seen := map[string]bool{}
	var refs []PackageRef
	add := func(name, version string) {
		if name == "" || version == "" {
			return
		}
		composite := name + "@" + version
		if seen[composite] {
			return
		}
		seen[composite] = true
		refs = append(refs, PackageRef{
			Ecosystem: intel.EcosystemNPM,
			Name:      name,
			Version:   version,
			Path:      target.Path,
			Source:    "yarn.lock",
		})
	}

	lines := strings.Split(content, "\n")
	i := 0
	for i < len(lines) {
		line := lines[i]
		// A block header is non-indented and ends with ':'. Skip blanks,
		// comments, indented body lines, and the __metadata: block.
		if line == "" || line[0] == ' ' || line[0] == '\t' || strings.HasPrefix(line, "#") ||
			!strings.HasSuffix(strings.TrimRight(line, " "), ":") || strings.HasPrefix(line, "__metadata:") {
			i++
			continue
		}

		resolution := ""
		j := i + 1
		for j < len(lines) {
			b := lines[j]
			// Only the next non-indented header ends the block. A blank
			// line does NOT (Berry separates blocks with a blank, but a
			// hand-edited block can carry an internal blank before its
			// resolution: line, and that must not hide the package).
			if b != "" && b[0] != ' ' && b[0] != '\t' {
				break
			}
			if resolution == "" {
				if m := yarnBerryResolutionRe.FindStringSubmatch(b); m != nil {
					resolution = m[1]
				}
			}
			j++
		}

		if name, version, ok := yarnBerryNameVersion(resolution); ok {
			add(name, version)
		}
		i = j
	}

	sort.Slice(refs, func(i, j int) bool {
		return refs[i].Name+"@"+refs[i].Version < refs[j].Name+"@"+refs[j].Version
	})
	return refs, nil
}

// yarnBerryNameVersion returns the real package name AND version from a
// Berry npm resolution -- both from this single resolved locator, so a
// disagreeing `version:` field cannot fabricate a tuple. Real Yarn
// normalizes an aliased resolution to the real package --
// `my-lodash@npm:lodash@4.17.20` resolves to `lodash@npm:4.17.20`
// (verified against Yarn 4; the alias survives only in the descriptor
// key, which this parser does not read). The text after `@npm:` is the
// resolved reference; it is either:
//
//	bare version       `lodash@npm:4.17.20`        -> name before @npm:, version = the bare value
//	embedded name@ver  `alias@npm:node-ipc@9.2.3`  -> name = node-ipc, version = 9.2.3
//
// Handling both shapes makes the result correct whether Yarn normalizes
// the resolution or ever retains the alias ident, so an alias never
// hides the real package. ok=false when there is no `@npm:` protocol
// (workspace:/patch:/git/... are not registry packages), the name is not
// a usable npm identifier, or the version is not an exact resolved
// version.
func yarnBerryNameVersion(resolution string) (name, version string, ok bool) {
	cur := resolution
	for {
		idx := strings.Index(cur, "@npm:")
		if idx <= 0 {
			return "", "", false
		}
		nameBefore := cur[:idx]
		after := cur[idx+len("@npm:"):]
		// Peel a nested alias layer (`alias@npm:real@npm:version`): the
		// real locator is what follows this `@npm:`.
		if strings.Contains(after, "@npm:") {
			cur = after
			continue
		}
		// Strip Yarn resolution metadata: `::key=val...` and `#builtin<...>`.
		if i := strings.Index(after, "::"); i >= 0 {
			after = after[:i]
		}
		if i := strings.IndexByte(after, '#'); i >= 0 {
			after = after[:i]
		}
		// A '@' in `after` (past any leading scope '@') means it carries
		// an embedded name@version -- the real package -- so name/version
		// split at that final '@'. Otherwise `after` is a bare version
		// and the name is the segment before this `@npm:`.
		if at := strings.LastIndexByte(after, '@'); at > 0 {
			name, version = after[:at], after[at+1:]
		} else {
			name, version = nameBefore, after
		}
		break
	}
	canonical, valid := validNPMName(name)
	if !valid || !exactNpmVersionRe.MatchString(version) {
		return "", "", false
	}
	return canonical, version, true
}

package packagecheck

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/garagon/aguara/internal/intel"
)

// bunPackagesKeyRe marks the start of the resolved "packages" object in a
// bun.lock file.
var bunPackagesKeyRe = regexp.MustCompile(`^\s*"packages"\s*:\s*\{`)

// bunEntryRe matches a resolved package entry inside that object: a
// quoted key whose value is an array whose first element is the resolved
// "<name>@<version>" string. Group 1 captures that first element.
var bunEntryRe = regexp.MustCompile(`^\s*"(?:[^"\\]|\\.)*"\s*:\s*\[\s*"([^"]+)"`)

// ParseBunLock reads a Bun text lockfile (bun.lock, lockfileVersion 1+)
// and returns the declared npm packages. It is the Bun counterpart to
// ParsePNPMLock / ParseYarnLock: a freshly cloned Bun project carries
// bun.lock but no node_modules, so
//
//	git clone <bun repo>
//	aguara check .
//
// audits the locked set before `bun install` runs. Bun installs from the
// npm registry, so refs land in intel.EcosystemNPM with Source="bun.lock".
//
// Only the TEXT bun.lock is parsed. The legacy binary bun.lockb is out of
// scope (it cannot be read without executing Bun, which would break the
// offline contract). bun.lock is JSONC -- it carries trailing commas, so
// encoding/json rejects it -- so the parser is line-based, like the yarn
// v1 parser, rather than depending on a JSONC decoder.
//
// Each entry in the packages object has the resolved "<name>@<version>"
// as its array's first element, and Bun normalizes aliases there: an
// alias key like "my-lodash" still records its first element as the REAL
// package ("lodash@4.17.20"). Reading the first element therefore matches
// the real registry package, so an alias cannot hide a compromised
// dependency behind a local name. Conservative, mirroring the other npm
// parsers: an entry is emitted only when the first element maps to a
// usable npm name and an exact resolved version; anything with a protocol
// (git/file/workspace/...) or a range is skipped, and results dedupe on
// (name, version) in deterministic order.
func ParseBunLock(target Target) ([]PackageRef, error) {
	data, err := os.ReadFile(target.Path)
	if err != nil {
		return nil, fmt.Errorf("open bun.lock: %w", err)
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
			Source:    "bun.lock",
		})
	}

	inPackages := false
	// Track object depth so only the TOP-LEVEL "packages" map is parsed.
	// depth is the object nesting before the current line: the root
	// object's direct keys (lockfileVersion, workspaces, packages) sit at
	// depth 1. A nested "packages" key (e.g. a workspace member at path
	// "packages" under "workspaces") sits deeper and is ignored, so the
	// real resolved map is not missed.
	depth := 0
	// Normalize CRLF so Windows checkouts parse identically.
	content := strings.ReplaceAll(string(data), "\r\n", "\n")
	for _, line := range strings.Split(content, "\n") {
		net := strings.Count(line, "{") - strings.Count(line, "}")
		if inPackages {
			if m := bunEntryRe.FindStringSubmatch(line); m != nil {
				if name, version, ok := splitNameVersion(m[1]); ok {
					add(name, version)
				}
			}
			// Entry lines balance their own braces (the inline dependencies
			// object); the packages map's closing "}" drops depth back to
			// the top level, ending the scan.
			depth += net
			if depth <= 1 {
				break
			}
			continue
		}
		if depth == 1 && bunPackagesKeyRe.MatchString(line) {
			inPackages = true
		}
		depth += net
	}

	sort.Slice(refs, func(i, j int) bool {
		return refs[i].Name+"@"+refs[i].Version < refs[j].Name+"@"+refs[j].Version
	})
	return refs, nil
}

// splitNameVersion splits a resolved "<name>@<version>" spec (scoped or
// unscoped) into a usable npm (name, version), returning ok=false when
// the name is not a valid npm identifier or the version is not an exact
// resolved version (a protocol or range is rejected).
func splitNameVersion(spec string) (name, version string, ok bool) {
	spec = strings.TrimSpace(spec)
	at := strings.LastIndexByte(spec, '@')
	if at <= 0 { // no '@', or a leading '@' with no version separator
		return "", "", false
	}
	rawName, version := spec[:at], spec[at+1:]
	canonical, valid := validNPMName(rawName)
	if !valid || !isExactYarnVersion(version) {
		return "", "", false
	}
	return canonical, version, true
}

package packagecheck

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/garagon/aguara/internal/intel"
)

// nodeModulesSeg is the path segment npm uses to nest installed
// dependencies in a lockfileVersion 2/3 `packages` map key.
const nodeModulesSeg = "node_modules/"

// nonRegistryVersionPrefixes are version-string prefixes that mark a
// dependency as resolved from somewhere other than the npm registry.
// A package-lock.json entry whose `version` begins with one of these
// cannot be confidently mapped to a registry (npm, name, version)
// tuple, so the parser skips it rather than risk matching a local /
// git / aliased package against an unrelated npm advisory of the same
// name.
var nonRegistryVersionPrefixes = []string{
	"file:", "link:", "workspace:", "git+", "git:", "ssh:", "npm:", "http:", "https:",
}

// nonRegistryResolvedPrefixes are `resolved` URL prefixes that mark a
// non-registry source. Registry entries resolve to an https tarball
// (https://registry.npmjs.org/...), so https is NOT a skip signal
// here; only the unambiguously non-registry git / file schemes are.
var nonRegistryResolvedPrefixes = []string{
	"file:", "git+", "git:", "ssh:",
}

// plPackagesEntry is a value in the lockfileVersion 2/3 `packages`
// map. Its own `dependencies` / `devDependencies` / `peerDependencies`
// fields are name->version-range STRING maps mirroring the manifest,
// NOT the resolved tree — they are intentionally not modelled here so
// the JSON decoder ignores them. The install graph in v2/v3 lives
// entirely in the flat `packages` map keys, so there is nothing to
// recurse into.
type plPackagesEntry struct {
	Version  string `json:"version"`
	Resolved string `json:"resolved"`
	Link     bool   `json:"link"`
}

// plDepEntry is a node in the lockfileVersion 1 `dependencies` tree.
// Here `dependencies` IS the nested resolved tree (name->object), so
// it is modelled and recursed; the sibling `requires` field (a
// name->range string map) is ignored by not being declared.
type plDepEntry struct {
	Version      string                `json:"version"`
	Resolved     string                `json:"resolved"`
	Link         bool                  `json:"link"`
	Dependencies map[string]plDepEntry `json:"dependencies"`
}

// packageLock is the minimal package-lock.json surface the parser
// reads. `packages` is present for lockfileVersion 2 and 3 (and is
// authoritative when present, so v2 — which also carries the legacy
// `dependencies` mirror — is never double-counted). `dependencies`
// is the lockfileVersion 1 recursive tree, used only when `packages`
// is absent.
type packageLock struct {
	Packages     map[string]plPackagesEntry `json:"packages"`
	Dependencies map[string]plDepEntry      `json:"dependencies"`
}

// ParsePackageLock reads a package-lock.json file and returns the
// declared npm packages. It is the pre-install counterpart to the
// installed-tree npm pipeline (incident.CheckNPM, which needs
// node_modules to exist): a freshly cloned npm repo carries
// package-lock.json but no node_modules, and this parser lets
//
//	git clone <npm repo>
//	aguara check .
//
// audit the locked dependency set against npm advisories before any
// `npm install` runs.
//
// Pure offline: no npm execution, no network. It reads the structured
// JSON rather than scanning text so the lockfileVersion 2/3 `packages`
// map keys (which encode the install path) are decoded deterministically.
//
// Conservative by design. An entry is emitted only when it maps with
// confidence to a registry (npm, name, version) tuple:
//
//   - the root project entry (packages[""]) is skipped;
//   - a `packages` key without a node_modules/ segment is a workspace
//     source directory, not an installed dependency, and is skipped;
//   - link: true (workspace symlink), a non-registry version prefix
//     (file: / link: / workspace: / git+ / git: / ssh: / npm: / http:
//     / https:), or a non-registry resolved scheme (file: / git+ /
//     git: / ssh:) all skip the entry;
//   - a missing or empty version skips the entry.
//
// Skipping loses coverage on those entries; the alternative — guessing
// a registry version for a git or aliased dependency — would invent a
// false match against an npm advisory. Better to under-report than to
// manufacture confidence.
func ParsePackageLock(target Target) ([]PackageRef, error) {
	data, err := os.ReadFile(target.Path)
	if err != nil {
		return nil, fmt.Errorf("open package-lock.json: %w", err)
	}
	var lock packageLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse package-lock.json: %w", err)
	}

	// Dedup on (name, version), not on path: the same (name, version)
	// can appear under many install paths in a v2/v3 packages map
	// (deduped or not by npm depending on the dependency graph) and as
	// repeated subtrees in a v1 dependencies tree. The user is exposed
	// to a compromised (name, version) once regardless of how many
	// node_modules paths host it, so collapsing here keeps the finding
	// count and packages_read aligned with the real exposure.
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
			Source:    "package-lock.json",
		})
	}

	if len(lock.Packages) > 0 {
		// lockfileVersion 2 / 3.
		for key, entry := range lock.Packages {
			name, ok := packageLockName(key)
			if !ok {
				continue
			}
			if !registryEntry(entry.Link, entry.Version, entry.Resolved) {
				continue
			}
			add(name, entry.Version)
		}
	} else {
		// lockfileVersion 1: recurse the dependencies tree. Recursion
		// is unconditional on the parent's registry status — a
		// non-registry parent (skipped) can still host registry
		// children worth auditing.
		var walk func(deps map[string]plDepEntry)
		walk = func(deps map[string]plDepEntry) {
			for name, entry := range deps {
				if canonical, ok := validNPMName(name); ok && registryEntry(entry.Link, entry.Version, entry.Resolved) {
					add(canonical, entry.Version)
				}
				if len(entry.Dependencies) > 0 {
					walk(entry.Dependencies)
				}
			}
		}
		walk(lock.Dependencies)
	}

	// Deterministic order by name@version. Map iteration above is
	// randomized; Aguara advertises deterministic scans, and the
	// runner preserves ref order into Hits and the CLI preserves Hits
	// order into Findings.
	sort.Slice(refs, func(i, j int) bool {
		return refs[i].Name+"@"+refs[i].Version < refs[j].Name+"@"+refs[j].Version
	})
	return refs, nil
}

// packageLockName extracts the package name from a lockfileVersion
// 2/3 `packages` map key. The key is the install path relative to the
// project root:
//
//	""                                        -> root project (skip)
//	node_modules/foo                          -> foo
//	node_modules/@scope/pkg                   -> @scope/pkg
//	packages/a/node_modules/foo               -> foo            (nested)
//	packages/a/node_modules/@scope/pkg        -> @scope/pkg     (nested)
//	packages/a                                -> workspace src  (skip)
//
// The name is whatever follows the LAST node_modules/ segment, so a
// nested dependency resolves to its own name regardless of depth. A
// key with no node_modules/ segment (other than "") is a workspace
// source directory, not an installed dependency, and is skipped.
func packageLockName(key string) (string, bool) {
	if key == "" {
		return "", false // root project
	}
	idx := strings.LastIndex(key, nodeModulesSeg)
	if idx < 0 {
		return "", false // workspace source dir, not an installed dep
	}
	return validNPMName(key[idx+len(nodeModulesSeg):])
}

// validNPMName validates that name is a well-formed npm package name
// (unscoped "foo" or scoped "@scope/pkg") and returns it unchanged.
// Anything else — an empty string, a stray extra path segment, a
// malformed scope — is rejected so the parser never emits an
// ambiguous name. The matcher applies npm-specific normalisation at
// lookup time; the parser only gates obvious malformations.
func validNPMName(name string) (string, bool) {
	if name == "" {
		return "", false
	}
	if strings.HasPrefix(name, "@") {
		// Scoped: exactly "@scope/pkg" — one slash, both parts present.
		parts := strings.SplitN(name, "/", 2)
		if len(parts) != 2 || len(parts[0]) < 2 || parts[1] == "" || strings.Contains(parts[1], "/") {
			return "", false
		}
		return name, true
	}
	if strings.Contains(name, "/") {
		return "", false // unexpected nesting for an unscoped name
	}
	return name, true
}

// registryEntry reports whether a lockfile entry resolves to a
// registry-installed package with a usable version. See the skip
// rules documented on ParsePackageLock. It takes the three fields
// shared by both entry shapes (v2/v3 packages map, v1 dependencies
// tree) so a single rule covers both.
func registryEntry(link bool, version, resolved string) bool {
	if link {
		return false
	}
	if version == "" {
		return false
	}
	for _, p := range nonRegistryVersionPrefixes {
		if strings.HasPrefix(version, p) {
			return false
		}
	}
	for _, p := range nonRegistryResolvedPrefixes {
		if strings.HasPrefix(resolved, p) {
			return false
		}
	}
	return true
}

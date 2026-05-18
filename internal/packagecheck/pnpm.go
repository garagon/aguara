package packagecheck

import (
	"fmt"
	"os"
	"strings"

	"github.com/garagon/aguara/internal/intel"
	"gopkg.in/yaml.v3"
)

// ParsePNPMLock reads a pnpm-lock.yaml file and returns the declared
// npm packages. pnpm installs from the npm registry, so refs land in
// intel.EcosystemNPM with Source="pnpm-lock.yaml" and match against
// OSV's npm advisories the same way package-lock.json or
// node_modules entries would.
//
// The primary user flow this unlocks is the pre-install audit:
//
//	git clone <pnpm repo>
//	aguara check .
//
// before any `pnpm install` has materialised node_modules. Without
// pnpm-lock.yaml parsing, that invocation returns ecosystems: []
// for the npm pipeline because the only npm signal Aguara reads
// today (node_modules/.pnpm store) is absent on a fresh clone.
//
// Pure offline: no pnpm execution, no network. The parser uses
// gopkg.in/yaml.v3 to read the structured packages map rather than
// regex-scanning the file so peer-dep / build-hook suffixes embedded
// in the package keys are handled deterministically.
//
// Non-registry sources (workspace:, file:, link:, github:, git:,
// http://, https://) are skipped — they are not addressable in the
// npm registry and matching them against npm advisories would
// false-positive on name collisions.
func ParsePNPMLock(target Target) ([]PackageRef, error) {
	data, err := os.ReadFile(target.Path)
	if err != nil {
		return nil, fmt.Errorf("open pnpm-lock.yaml: %w", err)
	}
	var lock struct {
		Packages map[string]any `yaml:"packages"`
	}
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse pnpm-lock.yaml: %w", err)
	}

	// Pre-allocate enough capacity for the common case; YAML maps
	// in Go have non-deterministic iteration order so callers that
	// depend on ordering should sort afterwards. The Runner doesn't.
	refs := make([]PackageRef, 0, len(lock.Packages))

	// Dedup on cleaned (name, version). pnpm encodes resolved
	// peer-dep relationships into the package key, so the same
	// underlying (name, version) can appear under multiple keys
	// when a package is consumed with different peer-dep
	// resolutions ("react@18.2.0(peer-a@1.0.0)" and
	// "react@18.2.0(peer-b@2.0.0)" both strip to react@18.2.0).
	// Without dedup here the runner would emit one Hit per
	// peer-variant and inflate both packages_read and
	// findings_count for compromised packages.
	seen := make(map[string]bool, len(lock.Packages))
	for key := range lock.Packages {
		name, version, ok := parsePnpmPackageKey(key)
		if !ok {
			continue
		}
		composite := name + "@" + version
		if seen[composite] {
			continue
		}
		seen[composite] = true
		refs = append(refs, PackageRef{
			Ecosystem: intel.EcosystemNPM,
			Name:      name,
			Version:   version,
			Path:      target.Path,
			Source:    "pnpm-lock.yaml",
		})
	}
	return refs, nil
}

// parsePnpmPackageKey extracts (name, version) from a pnpm-lock
// packages-map key. The key format pnpm uses is one of:
//
//	node-ipc@9.2.3                        (unscoped, modern)
//	/node-ipc@9.2.3                       (unscoped, older lockfile shape)
//	@scope/pkg@1.2.3                      (scoped, modern)
//	/@scope/pkg@1.2.3                     (scoped, older lockfile shape)
//	lodash@4.17.21_react@18.0.0           (peer-dep suffix, pre-v9)
//	react@18.2.0(some-peer@1.0.0)         (peer-dep suffix, v9+)
//
// The version portion after the LAST "@" is stripped of anything
// after a "_" or "(" so the matcher sees the actual installed
// version, not the peer-dep-decorated form.
//
// Returns ok=false for:
//
//   - bare names without a version ("node-ipc", "node-ipc@")
//   - non-registry sources (file:, link:, workspace:, github:, git:,
//     http:, https:): these are not addressable in the npm registry
//     and matching them against npm OSV records would false-positive
//     on name collisions (e.g. a local "lodash" link would inherit
//     every lodash advisory).
//   - keys we cannot parse into a clean (name, version) pair
//
// Conservative by design: better to under-emit than to surface false
// positives on shapes pnpm uses for non-registry packages.
func parsePnpmPackageKey(key string) (string, string, bool) {
	// Older lockfiles prefix entries with "/". Strip before the
	// source-prefix checks so "/file:..." and "file:..." are
	// treated identically.
	key = strings.TrimPrefix(key, "/")

	// Hard reject non-registry sources. Each prefix is a literal
	// pnpm spec; no wildcards.
	for _, prefix := range []string{
		"file:", "link:", "workspace:", "github:", "git:", "http:", "https:",
	} {
		if strings.HasPrefix(key, prefix) {
			return "", "", false
		}
	}

	// Two pnpm key formats are valid in the wild:
	//
	//   modern (v6+):    name@version           "@scope/pkg@1.2.3"
	//   legacy (v5):     name/version           "@scope/pkg/1.2.3"
	//
	// Try the modern shape first by locating the version-separating
	// "@". Correct rule:
	//   - scoped key  ("@scope/pkg@1.2.3"):  find the "@" AFTER the
	//     first "/"; that is the package/version boundary.
	//     LastIndex would land in a peer-dep suffix instead.
	//   - unscoped key ("node-ipc@1.2.3"):   first "@" is the
	//     separator; anything later is a peer-dep suffix.
	//
	// If no "@" sits in a valid position, fall back to the legacy
	// slash-separator shape (last "/" is the version boundary).
	// Without this fallback, lockfileVersion 5.x projects with
	// keys like "/lodash/4.17.21" or "/@types/node/20.5.0" would
	// silently produce zero packages_read even when the lockfile
	// declares compromised versions.
	var (
		name    string
		version string
	)
	if strings.HasPrefix(key, "@") {
		slash := strings.IndexByte(key, '/')
		if slash > 0 {
			if rel := strings.IndexByte(key[slash:], '@'); rel >= 0 {
				at := slash + rel
				name = key[:at]
				version = key[at+1:]
			}
		}
	} else {
		if at := strings.IndexByte(key, '@'); at > 0 {
			name = key[:at]
			version = key[at+1:]
		}
	}
	if name == "" {
		// Legacy v5 fallback: last "/" splits name from version.
		// Validate slash structure to avoid mis-classifying malformed
		// modern keys (like "@scope/pkg" with no version) as v5:
		//   - scoped v5 keys are "@scope/pkg/version" (2 slashes)
		//   - unscoped v5 keys are "name/version"     (1 slash)
		// "@scope/pkg" has 1 slash and would otherwise resolve to
		// (name="@scope", version="pkg"), which is wrong.
		lastSlash := strings.LastIndexByte(key, '/')
		if lastSlash <= 0 || lastSlash == len(key)-1 {
			return "", "", false
		}
		if strings.HasPrefix(key, "@") && strings.Count(key, "/") < 2 {
			return "", "", false
		}
		name = key[:lastSlash]
		version = key[lastSlash+1:]
	}
	if name == "" || version == "" {
		return "", "", false
	}

	// Strip peer-dep / build-hook suffix. Two encodings exist in
	// the wild:
	//   pre-v9: "react@18.2.0_react-dom@18.2.0"   (underscore separator)
	//   v9+:    "react@18.2.0(peer-dep@1.0.0)"    (paren wrapper)
	// SemVer build metadata uses "+", which is preserved.
	if i := strings.IndexAny(version, "_("); i >= 0 {
		version = version[:i]
	}
	if version == "" {
		return "", "", false
	}
	return name, version, true
}

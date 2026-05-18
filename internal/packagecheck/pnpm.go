package packagecheck

import (
	"fmt"
	"os"
	"sort"
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
	// Sort keys before iterating so the emitted refs land in
	// deterministic order. Go's map iteration is randomized; the
	// runner preserves the input order into Hits and the CLI
	// preserves Hits order into CheckResult.Findings, so without
	// this sort a pnpm lock with two or more matched packages
	// would produce different JSON / terminal finding order across
	// runs. Aguara advertises deterministic scans; the other
	// packagecheck parsers read line-by-line and are deterministic
	// for free.
	keys := make([]string, 0, len(lock.Packages))
	for k := range lock.Packages {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
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

	// Strip the parens-style peer-dep suffix from the key BEFORE
	// classifying scoped vs unscoped. v9+ encodes resolved peer
	// deps as "name@version(peer@version)" and the peer can itself
	// be scoped ("@commitlint/cli@19.6.1(@types/node@22.10.2)").
	// A scoped peer adds an extra "/" to the key, which would fool
	// the scoped slash-count heuristic into treating the key as v5
	// slash-form and splitting on the wrong "/". The peer suffix
	// is always after the version, so removing it pre-classification
	// is safe; the underscore-style suffix is removed downstream
	// from the version string itself.
	if i := strings.IndexByte(key, '('); i >= 0 {
		key = key[:i]
	}

	// Two pnpm key formats coexist in the wild:
	//
	//   modern (v6+):  name@version            "lodash@4.17.21"
	//                  @scope/pkg@version      "@scope/pkg@1.2.3"
	//   legacy (v5):   name/version            "lodash/4.17.21"
	//                  @scope/pkg/version      "@scope/pkg/1.2.3"
	//
	// Both shapes can be decorated with a peer-dep suffix (pre-v9
	// "..._peer@version" underscore, v9+ "...(peer@version)" parens).
	// The peer suffix is always AFTER the version, so peer-aware
	// stripping happens once after the (name, version) pair is picked.
	//
	// The tricky combination is legacy v5 slash-form with a peer
	// underscore: "lodash/4.17.21_react@18.0.0". The "@" in that
	// key belongs to the peer suffix, NOT the package/version
	// boundary. Picking the first "@" as the separator would
	// produce ("lodash/4.17.21_react", "18.0.0") and silently
	// drop the real package match. Decide modern vs v5 BEFORE
	// looking for the "@" separator.
	//
	// Decision rule:
	//   - scoped key (starts with "@"):
	//       modern if there is an "@" AFTER the first "/"
	//       v5     otherwise (slash-fallback)
	//   - unscoped key:
	//       v5     if there is a "/" AND ("/" appears before the
	//              first "@" OR there is no "@" at all)
	//       modern otherwise
	var (
		name    string
		version string
	)
	if strings.HasPrefix(key, "@") {
		// Slash count discriminates modern vs v5 for scoped keys:
		//   1 slash  -> "@scope/pkg@version" or "@scope/pkg" (modern)
		//   2+ slashes -> "@scope/pkg/version[_peer@...]" (v5)
		// Without this check, a v5 key with a peer-dep suffix
		// containing "@" (e.g. "@types/node/20.5.0_typescript@5.0.0")
		// would route through the modern branch and pick the peer
		// "@" as the version separator, producing
		// (name="@types/node/20.5.0_typescript", version="5.0.0").
		switch strings.Count(key, "/") {
		case 1:
			// Modern scoped form. The "@" AFTER the first slash
			// is the package/version boundary; any later "@"
			// belongs to a peer-dep suffix.
			slash := strings.IndexByte(key, '/')
			if rel := strings.IndexByte(key[slash:], '@'); rel >= 0 {
				at := slash + rel
				name = key[:at]
				version = key[at+1:]
			}
			// No "@" after the slash -> "@scope/pkg" without
			// a version. Leave name="" so the v5 fallback below
			// rejects via the >= 2 slashes guard.
		default:
			// 0 slashes -> malformed scoped (just "@something").
			// >= 2 slashes -> v5 form; leave name="" for v5
			//                slash-fallback below.
		}
	} else {
		firstAt := strings.IndexByte(key, '@')
		firstSlash := strings.IndexByte(key, '/')
		isV5SlashForm := firstSlash >= 0 && (firstAt < 0 || firstSlash < firstAt)
		if !isV5SlashForm && firstAt > 0 {
			name = key[:firstAt]
			version = key[firstAt+1:]
		}
		// v5 slash-form OR no "@" anywhere -> leave name="" for
		// v5 slash-fallback below.
	}
	if name == "" {
		// Legacy v5 fallback. Validate slash structure to avoid
		// mis-classifying malformed modern keys as v5:
		//   - scoped v5 keys are "@scope/pkg/version" (>= 2 slashes)
		//   - unscoped v5 keys are "name/version"     (>= 1 slash)
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

package packagecheck

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/garagon/aguara/internal/intel"
	"gopkg.in/yaml.v3"
)

// exactNpmVersionRe matches an exact, fully-resolved npm version: three
// numeric components with an optional prerelease/build suffix
// (1.2.3, 10.0.0-alpha.1, 2.1.5+build.7). It deliberately rejects range
// operators (^, ~, >, <, =, *, x), dist-tags (latest, next), and
// partial versions (9.2) so an alias whose right-hand side is not a
// pinned registry version is skipped rather than matched. pnpm always
// records resolved exact versions in the packages map, so this is the
// only form a real alias entry takes.
var exactNpmVersionRe = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]+)?$`)

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
// http://, https://, jsr:) are skipped — they are not addressable in
// the npm registry and matching them against npm advisories would
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
//     http:, https:, jsr:): these are not addressable in the npm registry
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
	// treated identically. Done FIRST so every classification below
	// (leading-prefix rejection, npm-alias routing) sees the same key.
	key = strings.TrimPrefix(key, "/")

	// Strip the parens-style peer-dep suffix up front, BEFORE any
	// source/alias classification. v9+ encodes resolved peer deps as
	// "name@version(peer@version)", and the peer can itself carry a
	// protocol ("foo@1.0.0(bar@npm:baz@2.0.0)") or be scoped
	// ("@commitlint/cli@19.6.1(@types/node@22.10.2)"). The suffix
	// belongs to the PEER, not this package: leaving it in would make
	// the "@npm:" / "@<protocol>:" tests below misread a peer's
	// protocol as this package's and either misroute the key to the
	// alias parser (dropping the real package) or reject it. The suffix
	// is always after the version, so removing it here is safe; a scoped
	// peer also adds an extra "/" that would otherwise fool the v5
	// slash-count heuristic. The underscore-style suffix is removed
	// downstream from the version string itself.
	if i := strings.IndexByte(key, '('); i >= 0 {
		key = key[:i]
	}

	// Hard reject non-registry sources whose key STARTS with the
	// protocol. Each prefix is a literal pnpm spec; no wildcards. This
	// runs before npm-alias routing so a slash-prefixed local key like
	// "/file:safe@npm:node-ipc@9.2.3" (now "file:safe@npm:...") is
	// rejected as the file dependency it is, not resolved to the npm
	// package buried in its path.
	for _, prefix := range []string{
		"file:", "link:", "workspace:", "github:", "git:", "http:", "https:", "jsr:",
	} {
		if strings.HasPrefix(key, prefix) {
			return "", "", false
		}
	}

	// Source/alias classification happens AFTER the (name, version)
	// split below, on the VERSION FIELD specifically (the text right
	// after the package name's "@"). That is where pnpm records the
	// install source: "npm:real@ver" for an alias, "workspace:" / "file:"
	// / ... for a non-registry alias, or a plain version otherwise.
	// Classifying the version field rather than substring-matching the
	// whole key means a protocol that appears only in a peer suffix
	// ("foo@1.0.0(bar@npm:baz@2.0.0)", "foo@1.0.0_bar@npm:baz@2.0.0") or
	// a local path is never mistaken for THIS package's source.

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
		// Scoped key. After the scope's "/" the package/version
		// boundary is the next "@" -- but ONLY if it precedes the next
		// "/". This single rule distinguishes all three scoped shapes
		// without a slash count:
		//   modern  "@scope/pkg@1.2.3"          -> "@" before any 2nd "/"
		//   alias   "@local/safe@npm:@s/e@1.2.3"-> "@npm:" before the
		//                                          real package's "/"
		//                                          (so scoped-alias ->
		//                                          scoped-real resolves)
		//   v5      "@scope/pkg/1.2.3[_peer@v]"  -> a "/" comes first,
		//                                          so any "@" is a peer
		//                                          suffix, not the
		//                                          boundary
		// The version field is classified (npm: alias / non-registry /
		// plain) after this split, so picking the boundary "@" here is
		// all that is needed.
		slash := strings.IndexByte(key, '/')
		if slash >= 0 {
			rest := key[slash+1:]
			atRel := strings.IndexByte(rest, '@')
			slashRel := strings.IndexByte(rest, '/')
			if atRel >= 0 && (slashRel < 0 || atRel < slashRel) {
				at := slash + 1 + atRel
				name = key[:at]
				version = key[at+1:]
			}
			// else: v5 slash form, or "@scope/pkg" without a version
			// -> leave name="" for the v5 fallback / rejection below.
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

	// The version field carries the install source.
	//
	//   "npm:real@ver" -> alias to a DIFFERENT real registry package;
	//                     resolve and match the REAL package, discarding
	//                     the local alias name.
	//   "file:" / "link:" / "workspace:" / "github:" / "git:" / "http(s):"
	//   / "jsr:" -> alias to a non-registry source; not matchable.
	//   anything else -> a plain (possibly peer-decorated) version.
	if real, isAlias := strings.CutPrefix(version, "npm:"); isAlias {
		return parseNpmAliasTarget(real)
	}
	for _, proto := range []string{
		"file:", "link:", "workspace:", "github:", "git:", "http:", "https:", "jsr:",
	} {
		if strings.HasPrefix(version, proto) {
			return "", "", false
		}
	}

	// Strip peer-dep / build-hook suffix. Two encodings exist in
	// the wild:
	//   pre-v9: "react@18.2.0_react-dom@18.2.0"   (underscore separator)
	//   v9+:    "react@18.2.0(peer-dep@1.0.0)"    (paren wrapper)
	// SemVer build metadata uses "+", which is preserved. (The paren
	// form was already stripped from the key at the top of the function.)
	if i := strings.IndexByte(version, '_'); i >= 0 {
		version = version[:i]
	}
	if version == "" {
		return "", "", false
	}
	return name, version, true
}

// parseNpmAliasTarget resolves the REAL registry package an npm: alias
// points at, from the spec on the RIGHT of "npm:". pnpm lets a
// dependency be installed under a different local name:
//
//	pnpm add safe-ipc@npm:node-ipc@9.2.3
//
// which lands in the lockfile packages map as "safe-ipc@npm:node-ipc@9.2.3";
// after the (name, version) split the version field is "npm:node-ipc@9.2.3"
// and this function receives "node-ipc@9.2.3". The alias name is
// intentionally discarded: matching against npm advisories must use the
// real package (node-ipc@9.2.3), or a compromised registry package hides
// behind an innocent local name.
//
// Forms handled (the paren peer suffix was already stripped from the key
// upstream):
//
//	node-ipc@9.2.3                              (unscoped real)
//	@redhat-cloud-services/rbac-client@2.1.5    (scoped real)
//	react@18.2.0_react-dom@18.2.0               (underscore peer suffix)
//
// Only an UNAMBIGUOUS alias with an exact pinned version is resolved.
// Returns ok=false when the spec lacks a version, carries a range or
// dist-tag instead of an exact version, or is empty/malformed. Same
// discipline as the rest of the parser: under-report before
// false-positive.
func parseNpmAliasTarget(spec string) (string, string, bool) {
	if spec == "" {
		return "", "", false
	}
	name, version, ok := parseModernRegistrySpec(spec)
	if !ok {
		return "", "", false
	}
	// Strip a pre-v9 underscore peer suffix from the version itself.
	if i := strings.IndexByte(version, '_'); i >= 0 {
		version = version[:i]
	}
	// Only an exact, resolved version is matchable; ranges and dist-tags
	// would false-positive against advisories for unrelated versions.
	if !exactNpmVersionRe.MatchString(version) {
		return "", "", false
	}
	return name, version, true
}

// parseModernRegistrySpec splits a modern npm registry spec
// ("node-ipc@9.2.3", "@scope/pkg@1.2.3") into (name, version). It is the
// resolved RIGHT-hand side of an npm: alias, which pnpm always writes in
// modern (name@version) form, never the legacy slash form. Returns
// ok=false for a missing version or a malformed scoped spec.
func parseModernRegistrySpec(spec string) (string, string, bool) {
	if strings.HasPrefix(spec, "@") {
		// Scoped: the package/version boundary is the "@" AFTER the
		// single "/" in "@scope/pkg".
		slash := strings.IndexByte(spec, '/')
		if slash < 0 {
			return "", "", false
		}
		rel := strings.IndexByte(spec[slash:], '@')
		if rel < 0 {
			return "", "", false // "@scope/pkg" with no version
		}
		at := slash + rel
		name, version := spec[:at], spec[at+1:]
		if name == "" || version == "" {
			return "", "", false
		}
		return name, version, true
	}
	at := strings.IndexByte(spec, '@')
	if at <= 0 {
		return "", "", false // bare name, no version
	}
	name, version := spec[:at], spec[at+1:]
	if version == "" {
		return "", "", false
	}
	return name, version, true
}

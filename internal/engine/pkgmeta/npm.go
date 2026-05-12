// Package pkgmeta inspects npm package manifests (package.json) for
// supply-chain risk patterns that combine static metadata signals into
// chains: install-time lifecycle hooks reachable through a git dependency,
// optional dependencies that resolve to executable git refs, and publish
// surfaces that share a job with install-time code paths.
//
// The analyzer is fully offline. It parses JSON into a small struct, runs
// a handful of string checks against the parsed fields, and never executes
// scripts or resolves the dependency tree. Findings stay chain-aware:
// single weak signals (a prepare script alone, a git dependency alone,
// publishConfig alone) never fire.
package pkgmeta

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"

	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
)

// AnalyzerName is the value reported in Finding.Analyzer for this engine.
const AnalyzerName = "pkgmeta"

// Rule IDs emitted by this analyzer.
const (
	RuleLifecycleGit    = "NPM_LIFECYCLE_GIT_001"
	RuleOptionalGit     = "NPM_OPTIONAL_GIT_001"
	RulePublishSurface  = "NPM_PUBLISH_SURFACE_001"
)

// Analyzer implements scanner.Analyzer for npm package metadata.
type Analyzer struct{}

// New returns a fresh npm package metadata analyzer.
func New() *Analyzer { return &Analyzer{} }

// Name returns the analyzer identifier.
func (a *Analyzer) Name() string { return AnalyzerName }

// Analyze parses the target if it is a package.json file and returns
// supply-chain findings. Non-manifest files and malformed JSON return nil.
func (a *Analyzer) Analyze(_ context.Context, target *scanner.Target) ([]types.Finding, error) {
	if !isManifestTarget(target) {
		return nil, nil
	}
	if len(target.Content) == 0 {
		return nil, nil
	}
	pkg, err := parseManifest(target.Content)
	if err != nil || pkg == nil {
		// Malformed JSON: leave pattern rules to flag what they can; pkgmeta
		// only reports on shapes it can confidently reason about.
		return nil, nil
	}
	pkg.path = target.RelPath
	pkg.raw = target.Content
	return detect(pkg), nil
}

// --- target gating ---

// isManifestTarget returns true for files named package.json. Checks both
// Path (when scanning a real repo) and RelPath (when scanning in-memory
// content with a hinted name).
func isManifestTarget(t *scanner.Target) bool {
	if t == nil {
		return false
	}
	for _, p := range []string{t.Path, t.RelPath} {
		if p == "" {
			continue
		}
		if filepath.Base(filepath.ToSlash(p)) == "package.json" {
			return true
		}
	}
	return false
}

// --- model ---

type manifest struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	Scripts              map[string]string `json:"scripts"`
	PublishConfig        json.RawMessage   `json:"publishConfig"`

	// Populated by Analyzer.Analyze before detection. Not part of the JSON
	// schema; lowercase to keep them out of struct-tag-based marshaling.
	path string
	raw  []byte
}

// --- parsing ---

func parseManifest(content []byte) (*manifest, error) {
	var m manifest
	if err := json.Unmarshal(content, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// sanitizeGitURL strips an embedded `user:password@` (or token `@`) from
// a dependency version string so a credentialed git spec like
// `git+https://user:token@github.com/org/repo.git` does not show up
// verbatim in scan output. Aguara's credential redaction only scrubs the
// credential-leak category, so supply-chain findings that emit a raw
// version must self-sanitize.
func sanitizeGitURL(version string) string {
	v := version
	// Only URL forms can carry credentials. Match the scheme then look
	// for an `@` that separates `userinfo` from `host`. Drop the
	// userinfo block.
	for _, scheme := range []string{"git+ssh://", "git+https://", "git+http://", "git+git://", "git://", "https://", "http://", "ssh://"} {
		if !strings.HasPrefix(strings.ToLower(v), scheme) {
			continue
		}
		rest := v[len(scheme):]
		at := strings.Index(rest, "@")
		slash := strings.Index(rest, "/")
		// `@` must appear before the first `/` to belong to userinfo;
		// otherwise it is part of a path (e.g. `@scope/...`).
		if at > 0 && (slash < 0 || at < slash) {
			return v[:len(scheme)] + rest[at+1:]
		}
		break
	}
	return v
}

// findLineOfQuotedKey returns the 1-based line number of the first
// occurrence of `"<key>"` in raw, or 0 if it is not present. Used to
// anchor findings to the manifest line declaring the offending entry so
// cross-rule findings on the same package.json get distinct line
// numbers and survive the scanner's default dedup pass.
func findLineOfQuotedKey(raw []byte, key string) int {
	if len(raw) == 0 || key == "" {
		return 0
	}
	needle := []byte(`"` + key + `"`)
	idx := bytes.Index(raw, needle)
	if idx < 0 {
		return 0
	}
	return bytes.Count(raw[:idx], []byte{'\n'}) + 1
}

// --- classifiers ---

// isGitDep reports whether a dependency value points at a git source rather
// than the npm registry. npm accepts several shorthand forms; we cover the
// ones that actually resolve to executable git content during install.
func isGitDep(version string) bool {
	v := strings.TrimSpace(version)
	if v == "" {
		return false
	}
	lower := strings.ToLower(v)
	// Strip an optional #ref fragment before suffix-matching so
	// "https://github.com/owner/repo.git#abc1234" still classifies as git.
	noFrag := lower
	if i := strings.Index(noFrag, "#"); i >= 0 {
		noFrag = noFrag[:i]
	}
	switch {
	case strings.HasPrefix(lower, "git+"):
		return true
	case strings.HasPrefix(lower, "git://"):
		return true
	case strings.HasPrefix(lower, "github:"):
		return true
	case strings.HasPrefix(lower, "gitlab:"):
		return true
	case strings.HasPrefix(lower, "bitbucket:"):
		return true
	case strings.HasPrefix(lower, "gist:"):
		return true
	// Any HTTP(S) URL ending in .git resolves as a git dependency in npm.
	// Covers github.com, gitlab.com, bitbucket.org, gitea instances, and
	// self-hosted hosts. The .git suffix on a real URL is unambiguous;
	// it does not collide with registry or filesystem specs.
	case strings.Contains(noFrag, "://") && strings.HasSuffix(noFrag, ".git"):
		return true
	}
	// owner/repo or owner/repo#ref shorthand: one slash, no protocol, no
	// version-range characters. Guard tightly so registry-pinned versions
	// like "^1.2.3" do not match.
	if strings.ContainsAny(v, " \t\n") {
		return false
	}
	if strings.ContainsAny(v, "^~<>=*|") {
		return false
	}
	if strings.HasPrefix(v, "file:") || strings.HasPrefix(v, "link:") || strings.HasPrefix(v, "workspace:") {
		return false
	}
	if strings.HasPrefix(v, "npm:") {
		return false
	}
	// require exactly one slash separating owner/repo, optionally followed
	// by a #ref. Excludes paths like "@scope/name@1.2.3".
	core := v
	if idx := strings.Index(core, "#"); idx >= 0 {
		core = core[:idx]
	}
	if strings.HasPrefix(core, "@") {
		// Scoped names use the registry, not a git shorthand.
		return false
	}
	if strings.Count(core, "/") != 1 {
		return false
	}
	return true
}

// lifecycleScripts are the npm script names that run automatically as
// part of `npm install`. A package that defines any of these AND pulls a
// dependency from a mutable git source can execute attacker code on the
// install user's machine.
//
// Strictly install-time per npm docs: preinstall, install, postinstall.
// prepare and its pre/post hooks also run during install (on git
// dependencies and when packing a local install). prepublishOnly,
// prepack, and postpack run only on `npm publish` / `npm pack` and are
// intentionally excluded so manifests that ship with publish-only hooks
// do not produce false-positive HIGH/CRITICAL findings.
var lifecycleScripts = []string{
	"preinstall",
	"install",
	"postinstall",
	"preprepare",
	"prepare",
	"postprepare",
}

// hasLifecycleScript reports whether scripts defines any install-time hook.
func hasLifecycleScript(scripts map[string]string) bool {
	for _, k := range lifecycleScripts {
		if _, ok := scripts[k]; ok {
			return true
		}
	}
	return false
}

// suspiciousPackageRoots matches dependency names that historically front
// install-time payloads in real supply-chain incidents. The list is
// intentionally short; broadening it costs false positives on legitimate
// setup/runtime libraries.
var suspiciousPackageRoots = []string{
	"setup",
	"install",
	"init",
	"runner",
	"runtime",
	"bootstrap",
	"loader",
}

// isSuspiciousPackageName reports whether a dependency name's last path
// segment matches a known incident fingerprint root, with or without a
// suffix (e.g. "setup", "setup-utils", "node-setup").
func isSuspiciousPackageName(name string) bool {
	if name == "" {
		return false
	}
	// Scoped names: @scope/leaf — only the leaf segment is the package's
	// own identifier; the scope is the publisher's namespace.
	tail := name
	if strings.HasPrefix(tail, "@") {
		if idx := strings.Index(tail, "/"); idx >= 0 {
			tail = tail[idx+1:]
		}
	}
	lower := strings.ToLower(tail)
	for _, root := range suspiciousPackageRoots {
		if lower == root {
			return true
		}
		if strings.HasPrefix(lower, root+"-") || strings.HasSuffix(lower, "-"+root) {
			return true
		}
		if strings.HasPrefix(lower, root) && len(lower) > len(root) && !isAlpha(lower[len(root)]) {
			return true
		}
	}
	return false
}

func isAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// scriptMentionsPublish reports whether any script runs an npm-flavored
// publish command. The publish ID is the sink that turns install-time
// execution into a registry-write capability.
func scriptMentionsPublish(scripts map[string]string) bool {
	needles := []string{
		"npm publish", "pnpm publish", "yarn publish", "yarn npm publish",
		"bun publish",
	}
	for _, body := range scripts {
		lower := strings.ToLower(body)
		for _, n := range needles {
			if strings.Contains(lower, n) {
				return true
			}
		}
	}
	return false
}

// scriptMentionsInstallOrBuild reports whether any script invokes a package
// manager install/build/test verb. This is the install-time-code half of
// the publish-surface chain.
func scriptMentionsInstallOrBuild(scripts map[string]string) bool {
	// Substring needles cover the common multi-word forms.
	needles := []string{
		"npm install", "npm i ", "npm ci", "npm run", "npm test", "npm exec",
		"pnpm install", "pnpm i ", "pnpm run", "pnpm test", "pnpm exec",
		"yarn install", "yarn run", "yarn test",
		"bun install", "bun i ", "bun run", "bun test",
	}
	// Exact short forms: when a script body is just `npm i`, `pnpm i`,
	// `yarn`, `bun i`, etc., the trailing-space needles above miss them.
	exact := map[string]bool{
		"npm i": true, "npm install": true, "npm ci": true,
		"pnpm i": true, "pnpm install": true,
		"yarn": true, "yarn install": true,
		"bun i": true, "bun install": true,
	}
	for _, body := range scripts {
		lower := strings.ToLower(body)
		for _, n := range needles {
			if strings.Contains(lower, n) {
				return true
			}
		}
		// Match the script body as a whole word after trimming, and also
		// each newline-separated line for multi-line shell scripts.
		for _, line := range strings.Split(lower, "\n") {
			if exact[strings.TrimSpace(line)] {
				return true
			}
		}
	}
	return false
}

// manifestReferencesProvenance reports whether the package manifest, taken
// as a whole, references a provenance / trusted-publishing / OIDC string.
// We run this against the raw bytes so a publishConfig.provenance flag,
// an "id-token" string in a script, or an "oidc" hint in arbitrary keys
// all count.
func manifestReferencesProvenance(raw []byte) bool {
	if len(raw) == 0 {
		return false
	}
	needles := []string{
		"provenance",
		"trusted-publishing",
		"trustedpublishing",
		"id-token",
		"id_token",
		"oidc",
		"actions_id_token_request",
	}
	lower := strings.ToLower(string(raw))
	for _, n := range needles {
		if strings.Contains(lower, n) {
			return true
		}
	}
	return false
}

// --- detection ---

// depEntry pairs a dependency name with its declared version and the
// dependency section it came from (so findings can name the chain
// precisely). Order is deterministic.
type depEntry struct {
	Name    string
	Version string
	Section string
}

func collectDeps(pkg *manifest) []depEntry {
	var out []depEntry
	for _, kv := range []struct {
		name string
		m    map[string]string
	}{
		{"dependencies", pkg.Dependencies},
		{"devDependencies", pkg.DevDependencies},
		{"optionalDependencies", pkg.OptionalDependencies},
		{"peerDependencies", pkg.PeerDependencies},
	} {
		names := make([]string, 0, len(kv.m))
		for k := range kv.m {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, n := range names {
			out = append(out, depEntry{Name: n, Version: kv.m[n], Section: kv.name})
		}
	}
	return out
}

func detect(pkg *manifest) []types.Finding {
	var out []types.Finding
	out = append(out, detectLifecycleGit(pkg)...)
	out = append(out, detectOptionalGit(pkg)...)
	if f := detectPublishSurface(pkg); f != nil {
		out = append(out, *f)
	}
	return out
}

// detectLifecycleGit emits NPM_LIFECYCLE_GIT_001 for each git-sourced
// dependency in a manifest that also defines an install-time lifecycle
// script. The chain is "mutable code source" + "auto-run hook" — either
// half on its own is fine.
func detectLifecycleGit(pkg *manifest) []types.Finding {
	if !hasLifecycleScript(pkg.Scripts) {
		return nil
	}
	var findings []types.Finding
	for _, d := range collectDeps(pkg) {
		if !isGitDep(d.Version) {
			continue
		}
		sev := types.SeverityHigh
		if d.Section == "optionalDependencies" && isSuspiciousPackageName(d.Name) {
			sev = types.SeverityCritical
		}
		safeVersion := sanitizeGitURL(d.Version)
		findings = append(findings, types.Finding{
			RuleID:   RuleLifecycleGit,
			RuleName: "Git dependency can execute lifecycle code during install",
			Severity: sev,
			Category: "supply-chain",
			Description: "package.json pulls " + d.Name + " from a git source (" + safeVersion +
				") and defines an npm install-time lifecycle script. On `npm install`, " +
				"the git ref can change between resolutions and the lifecycle script will " +
				"execute whatever code is at the resolved ref, with the install user's " +
				"environment.",
			FilePath:    pkg.path,
			Line:        findLineOfQuotedKey(pkg.raw, d.Name),
			MatchedText: d.Section + "." + d.Name + " = " + safeVersion + " + install-time script",
			Analyzer:    AnalyzerName,
			Confidence:  0.9,
			Remediation: "Pin npm dependencies to registry versions with lockfile integrity. " +
				"If a git source is required, audit the exact commit and use --ignore-scripts " +
				"during install. Remove install-time lifecycle hooks unless they are essential.",
		})
	}
	return findings
}

// detectOptionalGit emits NPM_OPTIONAL_GIT_001 for each optionalDependency
// resolving to a git source. Optional deps are special: they install
// silently on platforms where the resolution succeeds, so a git-sourced
// optional dep is a quieter compromise vector than the same shape in
// dependencies.
func detectOptionalGit(pkg *manifest) []types.Finding {
	if len(pkg.OptionalDependencies) == 0 {
		return nil
	}
	// When a lifecycle script is present, NPM_LIFECYCLE_GIT_001 already
	// covers every optional git dep with higher severity and a strictly
	// stronger description (install-time execution). Suppress the
	// optional-git rule in that case to avoid two findings that the
	// scanner's cross-rule dedup would silently collapse.
	if hasLifecycleScript(pkg.Scripts) {
		return nil
	}
	names := make([]string, 0, len(pkg.OptionalDependencies))
	for k := range pkg.OptionalDependencies {
		names = append(names, k)
	}
	sort.Strings(names)
	var findings []types.Finding
	for _, n := range names {
		v := pkg.OptionalDependencies[n]
		if !isGitDep(v) {
			continue
		}
		sev := types.SeverityMedium
		if isSuspiciousPackageName(n) {
			sev = types.SeverityHigh
		}
		safeVersion := sanitizeGitURL(v)
		findings = append(findings, types.Finding{
			RuleID:   RuleOptionalGit,
			RuleName: "Optional dependency resolves executable code from git",
			Severity: sev,
			Category: "supply-chain",
			Description: "optionalDependencies." + n + " resolves to a git source (" + safeVersion +
				"). Optional dependencies install silently when resolution succeeds, so a " +
				"mutable git ref here is a quieter supply-chain entry point than the same " +
				"shape in dependencies.",
			FilePath:    pkg.path,
			// Per-dep line anchor: multiple optional git deps get distinct
			// lines so the scanner's same-rule dedup keeps each one.
			Line:        findLineOfQuotedKey(pkg.raw, n),
			MatchedText: "optionalDependencies." + n + " = " + safeVersion,
			Analyzer:    AnalyzerName,
			Confidence:  0.8,
			Remediation: "Avoid git sources in optionalDependencies. If you must use one, pin " +
				"it to a specific commit and review the contents before each version bump.",
		})
	}
	return findings
}

// detectPublishSurface emits NPM_PUBLISH_SURFACE_001 when the package
// exposes a publish surface (publishConfig present, or scripts run a
// publish command) AND the same scripts also run install/build/test code
// AND the manifest references provenance / trusted-publishing / OIDC
// strings (i.e. the publish path is being given elevated trust).
func detectPublishSurface(pkg *manifest) *types.Finding {
	hasPublishConfig := len(pkg.PublishConfig) > 0 && strings.TrimSpace(string(pkg.PublishConfig)) != "null"
	hasPublishScript := scriptMentionsPublish(pkg.Scripts)
	if !hasPublishConfig && !hasPublishScript {
		return nil
	}
	if !scriptMentionsInstallOrBuild(pkg.Scripts) {
		return nil
	}
	if !manifestReferencesProvenance(pkg.raw) {
		return nil
	}
	// Anchor at publishConfig if declared, otherwise at the scripts block
	// where the publish command lives.
	line := findLineOfQuotedKey(pkg.raw, "publishConfig")
	if line == 0 {
		line = findLineOfQuotedKey(pkg.raw, "scripts")
	}
	return &types.Finding{
		RuleID:   RulePublishSurface,
		RuleName: "Package publish surface exposed to install-time code",
		Severity: types.SeverityHigh,
		Category: "supply-chain",
		Description: "package.json defines a publish surface (publishConfig or a publish " +
			"script) alongside install/build/test scripts and references provenance / " +
			"trusted-publishing / OIDC. Install-time scripts running in the same context " +
			"as the publish surface can mint or relay a trusted publishing token before " +
			"the publish step runs.",
		FilePath:    pkg.path,
		Line:        line,
		MatchedText: "publishConfig/publish script + install-or-build script + provenance/OIDC reference",
		Analyzer:    AnalyzerName,
		Confidence:  0.75,
		Remediation: "Split publishing into its own CI job that consumes pre-built, verified " +
			"artifacts. Grant trusted-publishing / OIDC scope only to the publish job and " +
			"keep install/build/test out of that job's execution graph.",
	}
}

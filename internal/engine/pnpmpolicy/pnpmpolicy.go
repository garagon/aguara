// Package pnpmpolicy is a small, auditable analyzer for pnpm
// supply-chain posture. It does NOT resolve package@version against
// threat intel (that is packagecheck's job); it reads the project's
// pnpm-workspace.yaml and reports where the configured trust controls
// have been weakened relative to pnpm v11 defaults.
//
// Design rules (locked in the spec):
//   - Single file. Only pnpm-workspace.yaml is a target. No
//     package.json read, no .npmrc, no cross-file correlation, no
//     pnpm-version inference. Severities are fixed, so the catalog
//     (explain / list-rules) and scan output never disagree.
//   - Defaults are never findings. The analyzer fires only on an
//     explicit value that is less safe than the v11 default; the
//     absence of a setting is treated as the (secure) default and
//     stays silent. This keeps it quiet on the millions of repos that
//     simply do not opt into extra hardening.
//   - yaml.Node parsing (not a flat struct) so: a single mis-typed
//     field cannot blind the whole analyzer, dynamic values like
//     ${AGE} are skipped rather than crashing, and every finding
//     carries the exact line of the offending field.
//
// Key resolution mirrors what pnpm actually loads: setting keys are
// matched case-insensitively with kebab-case and camelCase treated as
// the same setting (pnpm normalizes `block-exotic-subdeps` and
// `blockExoticSubdeps` to one value), and YAML merge keys (`<<:`) are
// expanded before evaluation so a value supplied through an anchor is
// not missed. Boolean values use YAML 1.1 spellings (true/false/yes/
// no/on/off, matching the js-yaml loader pnpm uses); a value that is
// not one of those tokens is treated as ambiguous and not evaluated,
// rather than coerced, so an explicit "false" is never mis-flagged as
// a dangerous opt-in.
package pnpmpolicy

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/garagon/aguara/internal/rulemeta"
	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
	"gopkg.in/yaml.v3"
)

// Rule IDs emitted by this analyzer.
const (
	RuleDangerousBuilds         = "PNPM_DANGEROUS_BUILDS_001"
	RuleStrictDepBuildsDisabled = "PNPM_STRICT_DEP_BUILDS_DISABLED_001"
	RuleExoticSubdepsDisabled   = "PNPM_EXOTIC_SUBDEPS_DISABLED_001"
	RuleTrustLockfile           = "PNPM_TRUST_LOCKFILE_001"
	RuleMinReleaseAgeDisabled   = "PNPM_MIN_RELEASE_AGE_DISABLED_001"
	RuleMinReleaseAgeNonStrict  = "PNPM_MIN_RELEASE_AGE_NON_STRICT_001"
	RuleTrustPolicyOff          = "PNPM_TRUST_POLICY_OFF_001"
	RuleLegacyBuildPolicy       = "PNPM_LEGACY_BUILD_POLICY_001"
	RuleBuildApprovalPending    = "PNPM_BUILD_APPROVAL_PENDING_001"
)

// AnalyzerName is the analyzer identifier surfaced on findings.
const AnalyzerName = rulemeta.AnalyzerPnpmPolicy

const category = "supply-chain"

// maxMergeDepth bounds YAML merge-key resolution (anchor cycles / deeply
// nested merges) so a hostile file cannot cause unbounded recursion.
const maxMergeDepth = 16

// legacyKeys are pnpm v10 build-policy settings removed or replaced in
// v11. Presence is a migration nudge (INFO), not a vulnerability.
var legacyKeys = []string{
	"onlyBuiltDependencies",
	"neverBuiltDependencies",
	"ignoredBuiltDependencies",
	"ignoreDepScripts",
	"onlyBuiltDependenciesFile",
}

// Analyzer implements scanner.Analyzer.
type Analyzer struct{}

// New constructs the pnpm-policy analyzer.
func New() *Analyzer { return &Analyzer{} }

// Name returns the analyzer identifier.
func (a *Analyzer) Name() string { return AnalyzerName }

// Analyze reads pnpm-workspace.yaml and reports weakened supply-chain
// controls. A non-target file, malformed YAML, or a file whose root is
// not a mapping all return no findings (and never panic).
func (a *Analyzer) Analyze(_ context.Context, target *scanner.Target) ([]types.Finding, error) {
	if !isTarget(target) {
		return nil, nil
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(target.Content, &doc); err != nil {
		// Malformed YAML: stay silent rather than guess or error.
		return nil, nil
	}
	root := mappingRoot(&doc)
	if root == nil {
		return nil, nil
	}

	// Flatten the root mapping with merge keys resolved, then index it
	// by normalized key so kebab-case and camelCase resolve to the same
	// setting. Precedence mirrors pnpm's config loading:
	//   - an explicit key always wins over a merged one;
	//   - among explicit keys, the last value wins (later overrides);
	//   - among merged keys, the first wins (YAML merge semantics).
	entries := flatten(root, 0)
	idx := make(map[string]entry, len(entries))
	explicitSet := make(map[string]bool, len(entries))
	for _, e := range entries {
		nk := normalizeKey(e.key)
		if !e.merged {
			idx[nk] = e // last explicit wins, and overrides any merged value
			explicitSet[nk] = true
			continue
		}
		if explicitSet[nk] {
			continue // an explicit value already won
		}
		if _, ok := idx[nk]; !ok {
			idx[nk] = e // first merged wins
		}
	}
	get := func(name string) (entry, bool) {
		e, ok := idx[normalizeKey(name)]
		return e, ok
	}

	src := strings.Split(string(target.Content), "\n")
	rel := target.RelPath
	if rel == "" {
		rel = target.Path
	}

	var findings []types.Finding
	emit := func(id, name, sev, desc string, line int, rem string) {
		findings = append(findings, types.Finding{
			RuleID:      id,
			RuleName:    name,
			Severity:    severity(sev),
			Category:    category,
			Description: desc,
			FilePath:    rel,
			Line:        line,
			MatchedText: srcLine(src, line),
			Remediation: rem,
			Analyzer:    AnalyzerName,
		})
	}

	// 1. dangerouslyAllowAllBuilds: true -> HIGH
	if e, ok := get("dangerouslyAllowAllBuilds"); ok {
		if b, parsed := yamlBool(e.value.Value); parsed && b {
			emit(RuleDangerousBuilds, "pnpm dangerouslyAllowAllBuilds enabled", "HIGH",
				"dangerouslyAllowAllBuilds: true lets every direct and transitive dependency run install-time lifecycle scripts without approval.",
				e.line,
				"Remove dangerouslyAllowAllBuilds: true and approve only the packages that need build scripts via allowBuilds (or `pnpm approve-builds`).")
		}
	}

	// 2. strictDepBuilds: false -> MEDIUM (v11 default is true).
	if e, ok := get("strictDepBuilds"); ok {
		if b, parsed := yamlBool(e.value.Value); parsed && !b {
			emit(RuleStrictDepBuildsDisabled, "pnpm strictDepBuilds disabled", "MEDIUM",
				"strictDepBuilds: false downgrades an unapproved build script from an install failure to a warning, so unreviewed install-time code can pass CI.",
				e.line,
				"Remove strictDepBuilds: false (or set it to true) so an unapproved build script fails the install and forces an explicit allowBuilds decision.")
		}
	}

	// 3. blockExoticSubdeps: false -> MEDIUM (v11 default is true).
	if e, ok := get("blockExoticSubdeps"); ok {
		if b, parsed := yamlBool(e.value.Value); parsed && !b {
			emit(RuleExoticSubdepsDisabled, "pnpm blockExoticSubdeps disabled", "MEDIUM",
				"blockExoticSubdeps: false allows transitive dependencies to resolve from git/tarball URLs instead of the registry, widening the code that can enter the tree without registry provenance.",
				e.line,
				"Remove blockExoticSubdeps: false (or set it to true). If a specific exotic subdep is required, vet and pin it explicitly rather than disabling the block globally.")
		}
	}

	// 4. trustLockfile: true -> MEDIUM (v11 default is false).
	if e, ok := get("trustLockfile"); ok {
		if b, parsed := yamlBool(e.value.Value); parsed && b {
			emit(RuleTrustLockfile, "pnpm trustLockfile enabled", "MEDIUM",
				"trustLockfile: true stops pnpm re-applying minimumReleaseAge and trustPolicy to lockfile entries, raising lockfile-poisoning risk on repos that take outside contributions.",
				e.line,
				"Remove trustLockfile: true so pnpm keeps verifying lockfile entries. Only consider it in fully closed repos where the lockfile is trusted end to end.")
		}
	}

	// 5 + 6. minimumReleaseAge / minimumReleaseAgeStrict.
	minAgeSet, minAgeVal := false, 0
	if e, ok := get("minimumReleaseAge"); ok {
		if n, parsed := yamlInt(e.value.Value); parsed {
			minAgeSet, minAgeVal = true, n
			if n == 0 {
				emit(RuleMinReleaseAgeDisabled, "pnpm minimumReleaseAge disabled", "LOW",
					"minimumReleaseAge: 0 is an explicit opt-out of the v11 default (1440 minutes), removing the wait window that protects against freshly published malicious versions.",
					e.line,
					"Remove minimumReleaseAge: 0 to use the default window, or set a positive value (e.g. 1440 for one day).")
			}
		}
	}
	// 6 fires only when minimumReleaseAge is explicitly set to a positive
	// value AND strict is explicitly false. Without an explicit positive
	// age, `minimumReleaseAgeStrict: false` may just be declaring the v11
	// compatibility default, so we stay silent.
	if e, ok := get("minimumReleaseAgeStrict"); ok && minAgeSet && minAgeVal > 0 {
		if b, parsed := yamlBool(e.value.Value); parsed && !b {
			emit(RuleMinReleaseAgeNonStrict, "pnpm minimumReleaseAge not strictly enforced", "LOW",
				"minimumReleaseAge is set to a positive value but minimumReleaseAgeStrict: false lets pnpm fall back to a version below the age threshold when no compatible alternative exists.",
				e.line,
				"Set minimumReleaseAgeStrict: true (or remove the false override) so the release-age threshold is always enforced.")
		}
	}

	// 7. trustPolicy: off (explicit) -> LOW. Compared on the literal
	// value because YAML resolves bare `off` as a string here; we want
	// the token, and absence never fires.
	if e, ok := get("trustPolicy"); ok {
		if strings.EqualFold(strings.TrimSpace(e.value.Value), "off") {
			emit(RuleTrustPolicyOff, "pnpm trustPolicy explicitly off", "LOW",
				"trustPolicy: off is set explicitly, opting the project out of trust-evidence checks (such as no-downgrade) that harden the lockfile.",
				e.line,
				"Consider a stricter trust policy such as no-downgrade. If off is intentional, document why; the finding only surfaces because the opt-out is explicit.")
		}
	}

	// 8. Legacy v10 build-policy settings -> INFO, one per present key.
	for _, k := range legacyKeys {
		if e, ok := get(k); ok {
			emit(RuleLegacyBuildPolicy, "pnpm legacy v10 build-policy setting", "INFO",
				fmt.Sprintf("%q is a pnpm v10 build-policy setting removed or replaced in v11; on v11 it no longer takes effect, so the intended build restriction may silently not apply.", e.key),
				e.line,
				"Migrate this setting to allowBuilds, the v11 mechanism for deciding which dependencies may run build scripts, and verify the resulting policy matches the original intent.")
		}
	}

	// 9. allowBuilds entries left undecided (null/empty placeholder) ->
	// MEDIUM, one per pending entry. The allowBuilds mapping is flattened
	// too so entries supplied through a merge key are seen.
	if e, ok := get("allowBuilds"); ok && e.value.Kind == yaml.MappingNode {
		seenPkg := make(map[string]bool)
		for _, ab := range flatten(e.value, 0) {
			if seenPkg[ab.key] {
				continue // a decision for this package already won
			}
			seenPkg[ab.key] = true
			if isNull(ab.value) {
				emit(RuleBuildApprovalPending, "pnpm allowBuilds entry pending decision", "MEDIUM",
					fmt.Sprintf("allowBuilds entry %q has no explicit true/false decision; the package has a build script still pending review.", ab.key),
					ab.line,
					"Set this allowBuilds entry to true (allow) or false (block) after reviewing the package's install-time script, or run `pnpm approve-builds`.")
			}
		}
	}

	return findings, nil
}

// entry is a resolved key/value pair: the value node, the line of the
// key (where a finding points), the original (un-normalized) key text
// for display, and whether it came from a merge key rather than being
// written directly at this mapping level (merged values lose to explicit
// ones during indexing).
type entry struct {
	key    string
	value  *yaml.Node
	line   int
	merged bool
}

// flatten returns the key/value pairs of a mapping node in source order,
// explicit keys first and then keys pulled in through YAML merge keys
// (`<<:`), each tagged with merged. Duplicates are kept; precedence is
// resolved by the caller's index so pnpm's last-wins (explicit) /
// first-wins (merged) rules can be applied across spellings.
func flatten(node *yaml.Node, depth int) []entry {
	return flattenVisited(node, depth, make(map[*yaml.Node]bool))
}

// flattenVisited is flatten with a visited-node set so a self-referential
// or fan-out merge (e.g. `<<: [*d, *d, *d]` where *d merges itself)
// expands each mapping node at most once. Merge keys are idempotent, so
// skipping an already-seen node is semantically correct and bounds the
// work to O(nodes) instead of exponential. Depth stays as a second
// guard.
func flattenVisited(node *yaml.Node, depth int, visited map[*yaml.Node]bool) []entry {
	if node == nil || node.Kind != yaml.MappingNode || depth > maxMergeDepth {
		return nil
	}
	if visited[node] {
		return nil
	}
	visited[node] = true

	var out, merged []entry
	var merges []*yaml.Node
	for i := 0; i+1 < len(node.Content); i += 2 {
		k, v := node.Content[i], node.Content[i+1]
		if k.Tag == "!!merge" || k.Value == "<<" {
			merges = append(merges, v)
			continue
		}
		out = append(out, entry{key: k.Value, value: v, line: k.Line})
	}
	for _, mn := range merges {
		for _, tgt := range mergeTargets(mn) {
			for _, e := range flattenVisited(tgt, depth+1, visited) {
				e.merged = true // anything reached through a merge is merged from here
				merged = append(merged, e)
			}
		}
	}
	return append(out, merged...)
}

// mergeTargets resolves the value of a `<<` merge key to the mapping
// node(s) it pulls in: an alias to a mapping, an inline mapping, or a
// sequence of either.
func mergeTargets(n *yaml.Node) []*yaml.Node {
	if n == nil {
		return nil
	}
	switch n.Kind {
	case yaml.AliasNode:
		return []*yaml.Node{n.Alias}
	case yaml.MappingNode:
		return []*yaml.Node{n}
	case yaml.SequenceNode:
		var out []*yaml.Node
		for _, it := range n.Content {
			switch it.Kind {
			case yaml.AliasNode:
				if it.Alias != nil {
					out = append(out, it.Alias)
				}
			case yaml.MappingNode:
				out = append(out, it)
			}
		}
		return out
	}
	return nil
}

// normalizeKey folds a well-formed kebab-case pnpm setting key to
// camelCase so the two spellings pnpm actually accepts compare equal (it
// treats "block-exotic-subdeps" and "blockExoticSubdeps" as one
// setting). The fold is case-sensitive and only joins single hyphens
// between non-empty segments. A spelling pnpm does NOT honor as that
// setting -- a smushed "blockexoticsubdeps", a mis-cased
// "BlockExoticSubdeps", or a malformed hyphenation
// ("block--exotic-subdeps", a leading/trailing hyphen) -- is returned
// unchanged so it cannot collapse onto a real key and produce a false
// finding.
func normalizeKey(s string) string {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "-") {
		for _, seg := range strings.Split(s, "-") {
			if seg == "" {
				return s // leading/trailing/doubled hyphen: not a valid kebab key
			}
		}
	}
	var b strings.Builder
	b.Grow(len(s))
	upNext := false
	for _, r := range s {
		if r == '-' {
			upNext = true
			continue
		}
		if upNext {
			b.WriteRune(unicode.ToUpper(r))
			upNext = false
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// mappingRoot returns the top-level mapping node of a parsed document,
// or nil if the document is empty or not a mapping at the root.
func mappingRoot(doc *yaml.Node) *yaml.Node {
	n := doc
	if n.Kind == yaml.DocumentNode {
		if len(n.Content) == 0 {
			return nil
		}
		n = n.Content[0]
	}
	if n.Kind == yaml.MappingNode {
		return n
	}
	return nil
}

// yamlBool interprets the YAML 1.1 boolean spellings pnpm config uses.
// Returns (value, true) for a recognized boolean token, (false, false)
// otherwise (dynamic values like ${X}, numbers, arbitrary strings). A
// non-boolean string is deliberately NOT coerced, so an explicit
// "false" is never read as a dangerous opt-in.
func yamlBool(s string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "yes", "on":
		return true, true
	case "false", "no", "off":
		return false, true
	default:
		return false, false
	}
}

// yamlInt parses an integer setting. Dynamic values (containing ${...})
// and non-numeric values return ok=false so the analyzer stays silent
// rather than guessing.
func yamlInt(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "${") {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}

// isNull reports whether a value node is an undecided placeholder: an
// explicit null/~, or an empty scalar (`key:` with nothing after it).
func isNull(n *yaml.Node) bool {
	if n == nil {
		return true
	}
	if n.Tag == "!!null" {
		return true
	}
	return n.Kind == yaml.ScalarNode && strings.TrimSpace(n.Value) == ""
}

// srcLine returns the trimmed source line (1-based) for MatchedText, or
// "" when out of range.
func srcLine(lines []string, n int) string {
	if n < 1 || n > len(lines) {
		return ""
	}
	return strings.TrimSpace(lines[n-1])
}

// severity maps the canonical string to a types.Severity. Unknown
// strings degrade to INFO rather than panicking; the metadata strings
// are all known so this is defensive only.
func severity(s string) types.Severity {
	sev, err := types.ParseSeverity(s)
	if err != nil {
		return types.SeverityInfo
	}
	return sev
}

// isTarget matches only pnpm-workspace.yaml (by base name, on either
// the absolute or relative path).
func isTarget(t *scanner.Target) bool {
	if t == nil {
		return false
	}
	for _, p := range []string{t.RelPath, t.Path} {
		if p == "" {
			continue
		}
		if filepath.Base(filepath.ToSlash(p)) == "pnpm-workspace.yaml" {
			return true
		}
	}
	return false
}

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
package pnpmpolicy

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

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
	fields := topLevelFields(root)

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
	if f, ok := fields["dangerouslyAllowAllBuilds"]; ok {
		if b, parsed := yamlBool(f.value.Value); parsed && b {
			emit(RuleDangerousBuilds, "pnpm dangerouslyAllowAllBuilds enabled", "HIGH",
				"dangerouslyAllowAllBuilds: true lets every direct and transitive dependency run install-time lifecycle scripts without approval.",
				f.line,
				"Remove dangerouslyAllowAllBuilds: true and approve only the packages that need build scripts via allowBuilds (or `pnpm approve-builds`).")
		}
	}

	// 2. strictDepBuilds: false -> MEDIUM (v11 default is true).
	if f, ok := fields["strictDepBuilds"]; ok {
		if b, parsed := yamlBool(f.value.Value); parsed && !b {
			emit(RuleStrictDepBuildsDisabled, "pnpm strictDepBuilds disabled", "MEDIUM",
				"strictDepBuilds: false downgrades an unapproved build script from an install failure to a warning, so unreviewed install-time code can pass CI.",
				f.line,
				"Remove strictDepBuilds: false (or set it to true) so an unapproved build script fails the install and forces an explicit allowBuilds decision.")
		}
	}

	// 3. blockExoticSubdeps: false -> MEDIUM (v11 default is true).
	if f, ok := fields["blockExoticSubdeps"]; ok {
		if b, parsed := yamlBool(f.value.Value); parsed && !b {
			emit(RuleExoticSubdepsDisabled, "pnpm blockExoticSubdeps disabled", "MEDIUM",
				"blockExoticSubdeps: false allows transitive dependencies to resolve from git/tarball URLs instead of the registry, widening the code that can enter the tree without registry provenance.",
				f.line,
				"Remove blockExoticSubdeps: false (or set it to true). If a specific exotic subdep is required, vet and pin it explicitly rather than disabling the block globally.")
		}
	}

	// 4. trustLockfile: true -> MEDIUM (v11 default is false).
	if f, ok := fields["trustLockfile"]; ok {
		if b, parsed := yamlBool(f.value.Value); parsed && b {
			emit(RuleTrustLockfile, "pnpm trustLockfile enabled", "MEDIUM",
				"trustLockfile: true stops pnpm re-applying minimumReleaseAge and trustPolicy to lockfile entries, raising lockfile-poisoning risk on repos that take outside contributions.",
				f.line,
				"Remove trustLockfile: true so pnpm keeps verifying lockfile entries. Only consider it in fully closed repos where the lockfile is trusted end to end.")
		}
	}

	// 5 + 6. minimumReleaseAge / minimumReleaseAgeStrict.
	minAgeSet, minAgeVal := false, 0
	if f, ok := fields["minimumReleaseAge"]; ok {
		if n, parsed := yamlInt(f.value.Value); parsed {
			minAgeSet, minAgeVal = true, n
			if n == 0 {
				emit(RuleMinReleaseAgeDisabled, "pnpm minimumReleaseAge disabled", "LOW",
					"minimumReleaseAge: 0 is an explicit opt-out of the v11 default (1440 minutes), removing the wait window that protects against freshly published malicious versions.",
					f.line,
					"Remove minimumReleaseAge: 0 to use the default window, or set a positive value (e.g. 1440 for one day).")
			}
		}
	}
	// 6 fires only when minimumReleaseAge is explicitly set to a positive
	// value AND strict is explicitly false. Without an explicit positive
	// age, `minimumReleaseAgeStrict: false` may just be declaring the v11
	// compatibility default, so we stay silent.
	if f, ok := fields["minimumReleaseAgeStrict"]; ok && minAgeSet && minAgeVal > 0 {
		if b, parsed := yamlBool(f.value.Value); parsed && !b {
			emit(RuleMinReleaseAgeNonStrict, "pnpm minimumReleaseAge not strictly enforced", "LOW",
				"minimumReleaseAge is set to a positive value but minimumReleaseAgeStrict: false lets pnpm fall back to a version below the age threshold when no compatible alternative exists.",
				f.line,
				"Set minimumReleaseAgeStrict: true (or remove the false override) so the release-age threshold is always enforced.")
		}
	}

	// 7. trustPolicy: off (explicit) -> LOW. Compared on the literal
	// value because YAML resolves bare `off` as a boolean; we want the
	// string token, and absence never fires.
	if f, ok := fields["trustPolicy"]; ok {
		if strings.EqualFold(strings.TrimSpace(f.value.Value), "off") {
			emit(RuleTrustPolicyOff, "pnpm trustPolicy explicitly off", "LOW",
				"trustPolicy: off is set explicitly, opting the project out of trust-evidence checks (such as no-downgrade) that harden the lockfile.",
				f.line,
				"Consider a stricter trust policy such as no-downgrade. If off is intentional, document why; the finding only surfaces because the opt-out is explicit.")
		}
	}

	// 8. Legacy v10 build-policy settings -> INFO, one per present key.
	for _, k := range legacyKeys {
		if f, ok := fields[k]; ok {
			emit(RuleLegacyBuildPolicy, "pnpm legacy v10 build-policy setting", "INFO",
				fmt.Sprintf("%q is a pnpm v10 build-policy setting removed or replaced in v11; on v11 it no longer takes effect, so the intended build restriction may silently not apply.", k),
				f.line,
				"Migrate this setting to allowBuilds, the v11 mechanism for deciding which dependencies may run build scripts, and verify the resulting policy matches the original intent.")
		}
	}

	// 9. allowBuilds entries left undecided (null/empty placeholder) ->
	// MEDIUM, one per pending entry.
	if f, ok := fields["allowBuilds"]; ok && f.value.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(f.value.Content); i += 2 {
			keyNode, valNode := f.value.Content[i], f.value.Content[i+1]
			if isNull(valNode) {
				emit(RuleBuildApprovalPending, "pnpm allowBuilds entry pending decision", "MEDIUM",
					fmt.Sprintf("allowBuilds entry %q has no explicit true/false decision; the package has a build script still pending review.", keyNode.Value),
					keyNode.Line,
					"Set this allowBuilds entry to true (allow) or false (block) after reviewing the package's install-time script, or run `pnpm approve-builds`.")
			}
		}
	}

	return findings, nil
}

// field pairs a top-level setting's value node with the line of its key
// (where the finding points).
type field struct {
	value *yaml.Node
	line  int
}

// topLevelFields indexes the root mapping by key. Later duplicate keys
// win, mirroring how a YAML loader resolves them.
func topLevelFields(root *yaml.Node) map[string]field {
	out := make(map[string]field, len(root.Content)/2)
	for i := 0; i+1 < len(root.Content); i += 2 {
		k, v := root.Content[i], root.Content[i+1]
		out[k.Value] = field{value: v, line: k.Line}
	}
	return out
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
// otherwise (dynamic values like ${X}, numbers, arbitrary strings).
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

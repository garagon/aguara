package aguara

import (
	"sort"

	"github.com/garagon/aguara/internal/rulecatalog"
)

// scanConfig holds the resolved configuration for a scan.
type scanConfig struct {
	customRulesDirs []string
	disabledRules   []string
	ruleOverrides   map[string]overrideEntry // keyed by canonical rule ID
	// overrideConflicts holds entries whose key named the same rule as
	// another key in the same WithRuleOverrides map; they are reported.
	overrideConflicts []overrideEntry
	minSeverity       Severity
	workers           int
	ignorePatterns    []string
	maxFileSize       int64
	category          string // only for ListRules
	toolName          string
	scanProfile       ScanProfile
	profileEnforced   []string
	deduplicateMode   DeduplicateMode
	stateDir          string
	redact            bool // scrub matched text from credential-leak findings
	targetPolicy      *bool
	lenientConfig     bool // skip invalid rule configuration instead of failing
}

// WithTrustedTargetPolicy allows files being scanned to suppress findings via
// .aguaraignore and inline aguara-ignore directives. Public scanning APIs
// treat their input as untrusted by default; this option is the explicit
// caller-controlled opt-in for trusted project policy.
func WithTrustedTargetPolicy() Option {
	return func(c *scanConfig) {
		enabled := true
		c.targetPolicy = &enabled
	}
}

// WithUntrustedTarget prevents files being scanned from suppressing findings
// via .aguaraignore or inline aguara-ignore directives. Use it when a cloned
// repository or external content is the object of the trust decision.
func WithUntrustedTarget() Option {
	return func(c *scanConfig) {
		enabled := false
		c.targetPolicy = &enabled
	}
}

// Option configures a scan operation.
type Option func(*scanConfig)

// WithCustomRules loads additional YAML rules from one or more directories.
// Repeated use accumulates: WithCustomRules(pack), WithCustomRules(userDir)
// loads both, in that order. Empty strings are ignored, and a directory
// listed more than once is loaded once.
func WithCustomRules(dirs ...string) Option {
	return func(c *scanConfig) {
		for _, dir := range dirs {
			if dir != "" {
				c.customRulesDirs = append(c.customRulesDirs, dir)
			}
		}
	}
}

// WithDisabledRules excludes specific rule IDs from scanning. IDs are
// case-insensitive and must name a rule in the catalog (built-in, analyzer
// or a rule loaded with WithCustomRules); an unknown ID is a ConfigError
// unless WithLenientConfig is set. Repeated use accumulates.
func WithDisabledRules(ids ...string) Option {
	return func(c *scanConfig) {
		c.disabledRules = append(c.disabledRules, ids...)
	}
}

// WithRuleOverrides applies severity overrides, disables rules, or scopes
// rules to tools, for pattern and analyzer-emitted rules alike. A severity
// override replaces the severity of every finding of that rule (a finding
// inside a Markdown code block in ordinary documentation is lowered one
// level from it, as with a pattern rule's own severity; in SKILL.md and
// agent instruction files it keeps the full severity). Keys are rule IDs
// (case-insensitive) and must name a rule in the catalog. Severity must be
// one of critical, high, medium, low or info, and ApplyToTools and
// ExemptTools are mutually exclusive. A problem with an override is a
// ConfigError unless WithLenientConfig is set.
//
// Repeated use merges the maps: a later entry for the same rule replaces an
// earlier one, also when the keys differ only in letter case. Within one
// map, two keys that name the same rule are a
// ConfigProblemConflictingOverride; with WithLenientConfig the key that
// sorts first is kept. The map is copied, so changing it afterwards has no
// effect.
func WithRuleOverrides(overrides map[string]RuleOverride) Option {
	return func(c *scanConfig) {
		if c.ruleOverrides == nil && len(overrides) > 0 {
			c.ruleOverrides = make(map[string]overrideEntry, len(overrides))
		}
		keys := make([]string, 0, len(overrides))
		for key := range overrides {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		inThisCall := make(map[string]bool, len(keys))
		for _, key := range keys {
			ovr := overrides[key]
			ovr.ApplyToTools = append([]string(nil), ovr.ApplyToTools...)
			ovr.ExemptTools = append([]string(nil), ovr.ExemptTools...)
			entry := overrideEntry{key: key, override: ovr}
			id := rulecatalog.CanonicalID(key)
			if inThisCall[id] {
				c.overrideConflicts = append(c.overrideConflicts, entry)
				continue
			}
			inThisCall[id] = true
			c.ruleOverrides[id] = entry
		}
	}
}

// overrideEntry is one WithRuleOverrides entry, keyed in scanConfig by its
// canonical rule ID. key keeps the spelling the caller used, for problems.
type overrideEntry struct {
	key      string
	override RuleOverride
}

// WithLenientConfig makes rule configuration problems non-fatal, as they
// were before ConfigError existed: a custom rule that does not compile is
// skipped, a custom rule whose ID is already defined is skipped (the
// existing rule is kept), an unknown rule ID in WithDisabledRules,
// WithRuleOverrides or WithProfileEnforcedRules is ignored, an invalid
// override severity is ignored (the rule keeps its severity and the rest of
// the override still applies), when an override sets both ApplyToTools and
// ExemptTools, ApplyToTools is used, and a rule that is both disabled and
// named in WithProfileEnforcedRules stays enabled and enforced (the
// enforcement wins, so a forwarded disable list cannot switch it off).
//
// The skipped problems are not discarded: Scanner.ConfigProblems returns
// them. The package-level Scan, ScanContent and ScanContentAs functions have
// no scanner to ask, so a caller that wants to read the problems builds the
// scanner with NewScanner. Prefer the default strict behaviour, which makes
// NewScanner and the scan functions return a *ConfigError, so a
// configuration mistake cannot silently weaken a scan.
func WithLenientConfig() Option {
	return func(c *scanConfig) {
		c.lenientConfig = true
	}
}

// WithMinSeverity sets the minimum severity threshold for reported findings.
func WithMinSeverity(sev Severity) Option {
	return func(c *scanConfig) {
		c.minSeverity = sev
	}
}

// WithWorkers sets the number of concurrent workers (default: NumCPU).
func WithWorkers(n int) Option {
	return func(c *scanConfig) {
		c.workers = n
	}
}

// WithIgnorePatterns sets file patterns to ignore during directory scanning.
func WithIgnorePatterns(patterns []string) Option {
	return func(c *scanConfig) {
		c.ignorePatterns = patterns
	}
}

// WithMaxFileSize sets the maximum accepted size of a file read from disk.
// Zero means use the default (50 MiB). An eligible file exceeding the limit
// causes ErrIncompleteScan; explicit ignore patterns still exclude files.
// This disk-read limit does not apply to ScanContent or ScanContentAs.
func WithMaxFileSize(bytes int64) Option {
	return func(c *scanConfig) {
		c.maxFileSize = bytes
	}
}

// WithCategory filters rules by category (only applies to ListRules).
func WithCategory(cat string) Option {
	return func(c *scanConfig) {
		c.category = cat
	}
}

// WithToolName sets the tool context for false-positive reduction.
// When set, built-in tool exemptions remove findings that are always false
// positives for that tool (e.g. MCPCFG_004 in WebFetch), and tool-scoped
// WithRuleOverrides entries apply. Tool names match case-insensitively.
func WithToolName(name string) Option {
	return func(c *scanConfig) {
		c.toolName = name
	}
}

// WithScanProfile sets the enforcement profile for the scan. Profiles only
// change ScanResult.Verdict; findings are always reported.
//
//   - ProfileStrict (default): a finding from a rule named in
//     WithProfileEnforcedRules blocks, whatever its severity; otherwise any
//     HIGH or CRITICAL finding blocks and any other finding flags.
//   - ProfileContentAware: a finding from an enforced rule blocks, whatever
//     its severity; otherwise any HIGH or CRITICAL finding flags; LOW,
//     MEDIUM and INFO findings alone are clean.
//   - ProfileMinimal: never blocks. A finding from an enforced rule, or any
//     HIGH or CRITICAL finding, flags; LOW, MEDIUM and INFO findings alone
//     are clean.
//
// No profile reports clean while a HIGH or CRITICAL finding remains, and an
// enforced rule never gets a weaker verdict under strict than under a
// relaxed profile. The verdict is computed from the findings that remain
// after disabled rules, tool exemptions (built-in or WithRuleOverrides) and
// WithMinSeverity have removed theirs, including an enforced rule's.
func WithScanProfile(profile ScanProfile) Option {
	return func(c *scanConfig) {
		c.scanProfile = profile
	}
}

// WithProfileEnforcedRules names rules whose findings block regardless of
// severity under every profile except ProfileMinimal, which flags them. IDs
// are case-insensitive and must exist in the catalog of loaded rules, so
// consumer-defined rule IDs need their rule pack loaded with WithCustomRules;
// an unknown ID is a ConfigError unless WithLenientConfig is set. The
// verdict only sees findings that remain after tool exemptions and
// WithMinSeverity, which can remove an enforced rule's finding. A rule that
// is also disabled
// (WithDisabledRules, or a Disabled entry in WithRuleOverrides) is a
// ConfigProblemConflictingOverride: a disabled rule never produces a
// finding, so the enforcement would do nothing. With WithLenientConfig the
// enforcement wins: the rule stays enabled and enforced, and the problem is
// returned by Scanner.ConfigProblems. Repeated use accumulates. With
// ProfileStrict, a finding from an enforced rule also blocks whatever its
// severity.
func WithProfileEnforcedRules(ids ...string) Option {
	return func(c *scanConfig) {
		c.profileEnforced = append(c.profileEnforced, ids...)
	}
}

// WithDeduplicateMode controls how findings on the same line are deduplicated.
// DeduplicateFull (default) removes cross-rule duplicates per line.
// DeduplicateSameRuleOnly keeps cross-rule findings, only removing same-rule duplicates.
func WithDeduplicateMode(mode DeduplicateMode) Option {
	return func(c *scanConfig) {
		c.deduplicateMode = mode
	}
}

// WithStateDir enables stateful scanning features (rug-pull detection)
// by persisting hashes to the specified directory.
func WithStateDir(dir string) Option {
	return func(c *scanConfig) {
		c.stateDir = dir
	}
}

// WithRedaction controls whether matched text from sensitive findings is
// replaced with "[REDACTED]" in the returned Finding. Enabled by default so
// secrets the scanner detects never appear in scan output, CI logs, or SARIF
// artifacts uploaded to GitHub Code Scanning.
//
// A finding is redacted when its rule (YAML `sensitive: true`) or its
// analyzer emit site (NLP_CRED_EXFIL_COMBO, toxicflow cred-bound pairs)
// marked it Sensitive, OR when its Category is "credential-leak" (legacy
// contract preserved for custom rules predating the Sensitive flag).
//
// Disable only when the consumer needs the raw match to programmatically
// verify or act on the detected secret (e.g. a remediation pipeline that
// cross-references the leak against a credential rotation tracker).
func WithRedaction(enabled bool) Option {
	return func(c *scanConfig) {
		c.redact = enabled
	}
}

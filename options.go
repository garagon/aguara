package aguara

// scanConfig holds the resolved configuration for a scan.
type scanConfig struct {
	customRulesDir  string
	disabledRules   []string
	ruleOverrides   map[string]RuleOverride
	minSeverity     Severity
	workers         int
	ignorePatterns  []string
	maxFileSize     int64
	category        string // only for ListRules
	toolName        string
	scanProfile     ScanProfile
	deduplicateMode DeduplicateMode
	stateDir        string
	redact          bool // scrub matched text from credential-leak findings
}

// Option configures a scan operation.
type Option func(*scanConfig)

// WithCustomRules loads additional rules from a directory.
func WithCustomRules(dir string) Option {
	return func(c *scanConfig) {
		c.customRulesDir = dir
	}
}

// WithDisabledRules excludes specific rule IDs from scanning.
func WithDisabledRules(ids ...string) Option {
	return func(c *scanConfig) {
		c.disabledRules = append(c.disabledRules, ids...)
	}
}

// WithRuleOverrides applies severity overrides or disables rules.
func WithRuleOverrides(overrides map[string]RuleOverride) Option {
	return func(c *scanConfig) {
		c.ruleOverrides = overrides
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

// WithMaxFileSize sets the maximum file size (in bytes) for scanned files.
// Zero means use the default (50 MB).
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
// When set, built-in tool exemptions and scan profiles can filter findings
// that are always false positives for that tool (e.g. TC-005 in Edit).
func WithToolName(name string) Option {
	return func(c *scanConfig) {
		c.toolName = name
	}
}

// WithScanProfile sets the enforcement profile for the scan.
// ProfileStrict (default) enforces all rules. ProfileContentAware only enforces
// MinimalEnforceRules (path traversal, system dir write, credentials).
// ProfileMinimal flags MinimalEnforceRules but doesn't block.
func WithScanProfile(profile ScanProfile) Option {
	return func(c *scanConfig) {
		c.scanProfile = profile
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

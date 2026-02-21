package aguara

// scanConfig holds the resolved configuration for a scan.
type scanConfig struct {
	customRulesDir string
	disabledRules  []string
	ruleOverrides  map[string]RuleOverride
	minSeverity    Severity
	workers        int
	ignorePatterns []string
	category       string // only for ListRules
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

// WithCategory filters rules by category (only applies to ListRules).
func WithCategory(cat string) Option {
	return func(c *scanConfig) {
		c.category = cat
	}
}

package skillpolicy

import "github.com/garagon/aguara/internal/rulemeta"

// RuleMetadata returns the catalog entries emitted by the skill-policy
// analyzer.
func RuleMetadata() []rulemeta.Rule {
	return []rulemeta.Rule{
		{
			ID:       RuleWildcardTools,
			Name:     "Skill pre-approves every tool",
			Severity: "MEDIUM",
			Category: "agent-trust",
			Analyzer: AnalyzerName,
			Description: "SKILL.md declares an allowed-tools wildcard instead of an explicit tool set. " +
				"The skill requests broad tool pre-approval when a supporting runtime honors this field.",
			Remediation: "Replace the wildcard with the smallest explicit set of tools the skill needs. " +
				"Scope command tools to reviewed command families instead of pre-approving every tool.",
		},
	}
}

var ruleInfo = rulemeta.Index(RuleMetadata())

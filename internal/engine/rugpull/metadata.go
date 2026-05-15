package rugpull

import "github.com/garagon/aguara/internal/rulemeta"

// RuleMetadata returns the catalog entries the rug-pull analyzer
// can emit. The analyzer only runs when --monitor is set (CLI) or
// WithStateDir is configured (library); the rule is in the catalog
// unconditionally so `aguara explain RUGPULL_001` works without
// needing to enable the detector first.
func RuleMetadata() []rulemeta.Rule {
	return []rulemeta.Rule{
		{
			ID:       "RUGPULL_001",
			Name:     "Tool description changed between scans",
			Severity: "HIGH",
			Category: "supply-chain",
			Analyzer: rulemeta.AnalyzerRugPull,
			Description: "MCP tool description (or other tracked content) changed " +
				"between this scan and the previous one. Detector compares SHA256 of " +
				"the relevant content against the state stored in --state-path " +
				"(default ~/.aguara/state.json). The classic 'rug-pull' shape: a " +
				"tool ships with a benign description, gets installed and trusted, " +
				"then a later update introduces malicious instructions while the " +
				"surrounding metadata stays unchanged.",
			Remediation: "Inspect the changed description against the prior version " +
				"(stored in state). If the change is intentional and benign, re-run " +
				"the scan to ack the new baseline. If unexpected, treat the tool as " +
				"compromised and remove it.",
		},
	}
}

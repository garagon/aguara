package rugpull

import "github.com/garagon/aguara/internal/rulemeta"

// RuleMetadata returns the catalog entries the rug-pull analyzer
// can emit. The analyzer only runs when --monitor is set (CLI) or
// WithStateDir is configured (library); the rule is in the catalog
// unconditionally so `aguara explain RUGPULL_001` works without
// needing to enable the detector first.
//
// Severity + Category MUST match what rugpull.go sets on the
// emitted Finding (currently CRITICAL + category rug-pull).
// A future change to the emit site must update this metadata in
// the same commit so list-rules / explain output stays consistent
// with scan output.
func RuleMetadata() []rulemeta.Rule {
	return []rulemeta.Rule{
		{
			ID:       "RUGPULL_001",
			Name:     "Tool description changed with dangerous content",
			Severity: "CRITICAL",
			Category: "rug-pull",
			Analyzer: rulemeta.AnalyzerRugPull,
			Description: "File content changed since last scan and now contains " +
				"suspicious patterns. The classic 'rug-pull' shape: a tool ships with " +
				"a benign description, gets installed and trusted, then a later update " +
				"introduces malicious instructions while the surrounding metadata stays " +
				"unchanged. Detector compares SHA256 of the tracked content against " +
				"the state stored in --state-path (default ~/.aguara/state.json) and " +
				"only fires when the new content also matches dangerous-pattern signals.",
			Remediation: "Inspect the changed content against the prior version " +
				"(stored in state). If the change is intentional and benign, re-run " +
				"the scan to ack the new baseline. If unexpected, treat the tool as " +
				"compromised and remove it.",
		},
	}
}

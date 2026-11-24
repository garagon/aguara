package skillchain

import "github.com/garagon/aguara/internal/rulemeta"

func RuleMetadata() []rulemeta.Rule {
	return []rulemeta.Rule{
		{
			ID:       RuleForcedHelperRisk,
			Name:     "Mandatory skill helper contains hidden high-risk behavior",
			Severity: "HIGH",
			Category: "agent-trust",
			Analyzer: AnalyzerName,
			Description: "An agent skill requires a local helper to run automatically or without user confirmation, " +
				"and the referenced helper contains a strong behavior that is not explained by the instruction: " +
				"a CRITICAL finding reported for the helper file itself, a HIGH finding from a behavior analyzer " +
				"(jsrisk, pyrisk, rsbuild, script-risk), an instruction-override payload, " +
				"network command execution, or direct VCS dependency installation. Sensitive and credential-leak " +
				"findings are not evidence. The helper is resolved by path inside the skill directory, whatever its extension.",
			Remediation: "Remove the mandatory or hidden execution path. Make helper use explicit and user-approved, " +
				"document its behavior, and replace dynamic command or unpinned dependency execution with reviewed, pinned inputs.",
		},
	}
}

var ruleInfo = rulemeta.Index(RuleMetadata())

package mcpcapability

import "github.com/garagon/aguara/internal/rulemeta"

// RuleMetadata preserves MCP_009's public identity after its YAML-rule migration.
func RuleMetadata() []rulemeta.Rule {
	return []rulemeta.Rule{{
		ID: RuleCapabilityEscalation, Name: "Capability escalation",
		Severity: "HIGH", Category: "mcp-attack", Analyzer: rulemeta.AnalyzerMCPCapability,
		Description:    "Detects broad literal capabilities or permissions in JSON/YAML configurations and explicit privilege requests in text. Reads direct scalar/list grants and add/allow/grant fields; drop, deny and unrelated fields are not grants. YAML aliases and merge keys are not resolved.",
		Remediation:    "Request only the minimum capabilities needed. Replace broad grants like 'all' with explicit, scoped permissions.",
		TruePositives:  []string{`{"capabilities": ["all"]}`, `permissions: admin`, "capabilities:\n  add: [ALL]", "request unrestricted capabilities"},
		FalsePositives: []string{"securityContext:\n  capabilities: {drop: [ALL]}", "capabilities: [read_files]\nallow: all"},
	}}
}

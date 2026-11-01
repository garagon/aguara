package kubepolicy

import "github.com/garagon/aguara/internal/rulemeta"

func RuleMetadata() []rulemeta.Rule {
	return []rulemeta.Rule{{
		ID: RuleIdentityCapabilities, Name: "Kubernetes workload requests identity-changing capabilities",
		Severity: "LOW", Category: "container-security", Analyzer: rulemeta.AnalyzerKubePolicy,
		DecisionImpact: rulemeta.DecisionImpactContext,
		Description:    "Identifies explicit SETUID or SETGID additions in supported Kubernetes container security contexts. These capabilities permit identity changes if effective at runtime; the declaration alone does not establish privilege escalation or host access. Unresolved templates, aliases and ambiguous syntax are not classified.",
		Remediation:    "Review whether the container needs these capabilities. Remove unnecessary additions and, where compatible with the workload, drop ALL and explicitly retain only required capabilities. Verify application behavior.",
	}}
}

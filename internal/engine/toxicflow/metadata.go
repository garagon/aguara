package toxicflow

import "github.com/garagon/aguara/internal/rulemeta"

// RuleMetadata returns the catalog entries for every rule this
// analyzer can emit. Single-file taint chains (TOXIC_*) and
// cross-file correlation chains (TOXIC_CROSS_*) are surfaced
// alongside so users can `aguara explain` either ID.
//
// Severity + Category MUST match the values toxicflow.go and
// crossfile.go set on the emitted Finding -- otherwise
// `list-rules --category toxic-flow` disagrees with what scan
// actually reports. Both emit sites currently use HIGH +
// toxic-flow; this catalog mirrors that. A future change that
// promotes one of these to CRITICAL must update BOTH the emit
// site and this metadata.
func RuleMetadata() []rulemeta.Rule {
	return []rulemeta.Rule{
		{
			ID:       "TOXIC_001",
			Name:     "Private data read with public output",
			Severity: "HIGH",
			Category: "toxic-flow",
			Analyzer: rulemeta.AnalyzerToxicFlow,
			Description: "Skill can read private data (credentials, SSH keys, env vars) " +
				"AND write to public channels (Slack, Discord, email). This combination " +
				"enables data exfiltration -- the credential read and the network sink " +
				"are independently benign, but co-occurring in the same skill they " +
				"compose into an exfil chain.",
			Remediation: "Either remove the network sink or break the data flow: pass " +
				"only non-credential identifiers across the boundary, and rotate any " +
				"credential the host has already used while this code was reachable.",
		},
		{
			ID:       "TOXIC_002",
			Name:     "Private data read with code execution",
			Severity: "HIGH",
			Category: "toxic-flow",
			Analyzer: rulemeta.AnalyzerToxicFlow,
			Description: "Skill can read private data AND execute arbitrary code. This " +
				"combination enables credential theft via dynamic code: the read pulls " +
				"the secret, the exec sends it anywhere the attacker chooses without " +
				"needing a static network sink in the source.",
			Remediation: "Drop one side of the chain. If the skill genuinely needs both, " +
				"split into separate, audited tools so the data flow is auditable.",
		},
		{
			ID:       "TOXIC_003",
			Name:     "Destructive actions with code execution",
			Severity: "HIGH",
			Category: "toxic-flow",
			Analyzer: rulemeta.AnalyzerToxicFlow,
			Description: "Skill has destructive capabilities AND can execute arbitrary " +
				"code. The combination enables ransomware-like attacks: the exec runs " +
				"the destructive payload, and the destructive surface erases forensic " +
				"traces afterwards.",
			Remediation: "Remove the destructive surface, OR split the destructive and " +
				"exec capabilities into separate skills so the agent's policy can refuse " +
				"the combination explicitly.",
		},
		{
			ID:       "TOXIC_CROSS_001",
			Name:     "Cross-file credential exfiltration across MCP tools",
			Severity: "HIGH",
			Category: "toxic-flow",
			Analyzer: rulemeta.AnalyzerToxicFlow,
			Description: "Cross-file correlation across MCP server tools in the same " +
				"directory: one tool reads credentials, a sibling tool issues a network " +
				"call. The split-across-files shape is a deliberate evasion of single-" +
				"file detectors; this rule looks at the directory as one unit.",
			Remediation: "Either remove the network sink in the sibling tool or move the " +
				"credential read behind explicit user consent. Cross-tool data flow " +
				"inside an MCP server should be auditable, not implicit.",
		},
		{
			ID:       "TOXIC_CROSS_002",
			Name:     "Cross-file env-to-exec chain across MCP tools",
			Severity: "HIGH",
			Category: "toxic-flow",
			Analyzer: rulemeta.AnalyzerToxicFlow,
			Description: "Cross-file correlation: one tool reads process environment, " +
				"another tool exposes a shell exec surface, and the data flow between " +
				"them is plausible (shared state, fs round-trip, ipc). Same evasion " +
				"shape as TOXIC_CROSS_001 but with command execution as the sink.",
			Remediation: "Decouple the read and exec surfaces. If one tool legitimately " +
				"needs env state for the other, expose it as an explicit, audited " +
				"parameter rather than relying on shared state.",
		},
		{
			ID:       "TOXIC_CROSS_003",
			Name:     "Cross-file destructive + exec combo across MCP tools",
			Severity: "HIGH",
			Category: "toxic-flow",
			Analyzer: rulemeta.AnalyzerToxicFlow,
			Description: "Cross-file correlation: one tool deletes / overwrites filesystem " +
				"state, another tool runs commands. The combination supports ransom-style " +
				"or evidence-wiping payloads distributed across the MCP server's tool " +
				"surface.",
			Remediation: "Treat the directory as actively malicious. The split shape is " +
				"deliberate evasion; remove the server and audit any agent runs that " +
				"have invoked its tools.",
		},
	}
}

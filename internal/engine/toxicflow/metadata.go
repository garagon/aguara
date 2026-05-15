package toxicflow

import "github.com/garagon/aguara/internal/rulemeta"

// RuleMetadata returns the catalog entries for every rule this
// analyzer can emit. Single-file taint chains (TOXIC_*) and
// cross-file correlation chains (TOXIC_CROSS_*) are surfaced
// alongside so users can `aguara explain` either ID.
func RuleMetadata() []rulemeta.Rule {
	return []rulemeta.Rule{
		{
			ID:       "TOXIC_001",
			Name:     "Credential read flows to network sink (same file)",
			Severity: "HIGH",
			Category: "supply-chain-exfil",
			Analyzer: rulemeta.AnalyzerToxicFlow,
			Description: "Single-file taint chain: a credential source (env-var read, " +
				"file read of ~/.ssh/, ~/.aws/credentials, etc.) reaches a network sink " +
				"(fetch, http.request, webhook URL) without sanitisation. Common shape " +
				"in supply-chain exfil payloads disguised as benign utility scripts.",
			Remediation: "Either remove the network sink or break the data flow: pass " +
				"only non-credential identifiers across the boundary, and rotate any " +
				"credential the host has already used while this code was reachable.",
		},
		{
			ID:       "TOXIC_002",
			Name:     "Environment variable flows to shell exec (same file)",
			Severity: "HIGH",
			Category: "command-execution",
			Analyzer: rulemeta.AnalyzerToxicFlow,
			Description: "Single-file taint chain: a process.env read (or os.environ in " +
				"Python) flows into a shell exec (child_process.exec, subprocess with " +
				"shell=True, os.system). User-controlled env vars become shell injection " +
				"vectors; the scanner flags the data flow regardless of whether the " +
				"specific env var name is sanitised at the source.",
			Remediation: "Switch to the argv form of subprocess invocation (execFile, " +
				"subprocess.run with a list and shell=False) so the env value cannot " +
				"break out of an argument boundary.",
		},
		{
			ID:       "TOXIC_003",
			Name:     "Destructive operation paired with arbitrary exec (same file)",
			Severity: "CRITICAL",
			Category: "command-execution",
			Analyzer: rulemeta.AnalyzerToxicFlow,
			Description: "Single-file taint chain: a destructive operation (rm -rf, " +
				"os.removedirs, fs.rmSync recursive) co-occurs with an arbitrary exec " +
				"sink. The combination matches credential-wiper and ransom-style " +
				"payloads that erase forensic traces after running.",
			Remediation: "Treat as actively malicious. Remove the file and audit recent " +
				"runs of any context that imported it.",
		},
		{
			ID:       "TOXIC_CROSS_001",
			Name:     "Cross-file credential exfiltration: one tool reads, another sends",
			Severity: "HIGH",
			Category: "supply-chain-exfil",
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
			Category: "command-execution",
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
			Severity: "CRITICAL",
			Category: "command-execution",
			Analyzer: rulemeta.AnalyzerToxicFlow,
			Description: "Cross-file correlation: one tool deletes / overwrites filesystem " +
				"state, another tool runs commands. The combination supports ransom-style " +
				"or evidence-wiping payloads distributed across the MCP server's tool surface.",
			Remediation: "Treat the directory as actively malicious. The split shape is " +
				"deliberate evasion; remove the server and audit any agent runs that " +
				"have invoked its tools.",
		},
	}
}

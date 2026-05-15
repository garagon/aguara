package nlp

import "github.com/garagon/aguara/internal/rulemeta"

// RuleMetadata returns the catalog entries for every rule the NLP
// injection analyzer can emit. Sourced from the rule IDs the
// analyzer hands to scanner.Finding in injection.go; this file is
// the canonical place users learn what each ID means.
func RuleMetadata() []rulemeta.Rule {
	return []rulemeta.Rule{
		{
			ID:       "NLP_HIDDEN_INSTRUCTION",
			Name:     "Hidden instruction inside non-instructional structure",
			Severity: "HIGH",
			Category: "prompt-injection",
			Analyzer: rulemeta.AnalyzerNLP,
			Description: "Markdown / JSON / YAML payload places imperative instructions " +
				"inside content the user reasonably reads as data (a table cell, an " +
				"example block, a tool description). The classifier flags imperative " +
				"verbs + role-switch language clustered inside structures that should " +
				"never carry agent instructions.",
			Remediation: "Move instructions to a section explicitly labelled as such, " +
				"or remove them. If the content is illustrative, wrap it in a code block " +
				"so the agent treats it as quoted text rather than directives.",
		},
		{
			ID:       "NLP_CODE_MISMATCH",
			Name:     "Code block contents diverge from surrounding instructions",
			Severity: "MEDIUM",
			Category: "prompt-injection",
			Analyzer: rulemeta.AnalyzerNLP,
			Description: "A markdown code block contains imperative instructions whose " +
				"intent does not match the surrounding prose (the prose says 'this is " +
				"an example of X', the code block actually says 'now do Y'). Pattern " +
				"matches prompt-injection payloads that hide instructions in a code-fence " +
				"to evade reviewer skim-reading.",
			Remediation: "Reconcile the code block with the surrounding description, or " +
				"escape the imperatives so they read as literal sample text.",
		},
		{
			ID:       "NLP_HEADING_MISMATCH",
			Name:     "Section heading does not match the section's instruction content",
			Severity: "MEDIUM",
			Category: "prompt-injection",
			Analyzer: rulemeta.AnalyzerNLP,
			Description: "Heading promises one topic (e.g. 'Configuration', 'Troubleshooting') " +
				"but the section body issues imperatives unrelated to that topic. Classic " +
				"injection structure: bury new directives under a benign-looking heading " +
				"so casual reviewers skip past them.",
			Remediation: "Align the heading with the section content, or remove the " +
				"unrelated imperatives if they were not intentional.",
		},
		{
			ID:       "NLP_AUTHORITY_CLAIM",
			Name:     "Authority-claim language in untrusted content",
			Severity: "MEDIUM",
			Category: "prompt-injection",
			Analyzer: rulemeta.AnalyzerNLP,
			Description: "Content claims authority Aguara cannot verify ('the maintainer says...', " +
				"'official policy...', 'as a system administrator...') and uses that claim to " +
				"justify an action. Common in indirect injection via documents the agent reads.",
			Remediation: "If the authority claim is real, route the instruction through a " +
				"channel the agent can verify (signed message, vetted config file). " +
				"Untrusted prose making authority claims is a prompt-injection vector.",
		},
		{
			ID:   "NLP_CRED_EXFIL_COMBO",
			Name: "Text combines credential access with network transmission",
			// Emit site: checkDangerousCombos in injection.go ->
			// SeverityCritical + category "exfiltration". The
			// catalog mirrors that exactly so list-rules and
			// scan output agree on triage.
			Severity: "CRITICAL",
			Category: "exfiltration",
			Analyzer: rulemeta.AnalyzerNLP,
			Description: "Same proximity window contains a credential-reference token " +
				"(API key, token, secret, password) AND a network-transmission verb " +
				"(send, post, upload, exfiltrate, leak). The classifier requires both " +
				"signals to be clustered, so generic security documentation does not " +
				"trip; when they cluster, the combination is the classic exfil shape.",
			Remediation: "Remove the imperative phrasing or relocate the credential " +
				"discussion into a code block / quoted example so the agent reads it as " +
				"data, not instructions.",
		},
		{
			ID:       "NLP_OVERRIDE_DANGEROUS",
			Name:     "Instruction override paired with dangerous capability",
			Severity: "CRITICAL",
			Category: "prompt-injection",
			Analyzer: rulemeta.AnalyzerNLP,
			Description: "Text contains an explicit instruction override ('ignore previous', " +
				"'forget your guidelines', 'new instructions') AND describes a dangerous " +
				"capability (shell exec, file read, network call). Highest-confidence " +
				"prompt-injection shape: an attacker telling the agent to drop its " +
				"prior context AND giving it a specific destructive action.",
			Remediation: "Treat the content as actively malicious. Remove the override + " +
				"capability pair, and audit any agent runs that have processed this content.",
		},
	}
}

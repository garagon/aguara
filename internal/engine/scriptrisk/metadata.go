package scriptrisk

import "github.com/garagon/aguara/internal/rulemeta"

// RuleMetadata returns the catalog entries emitted by the script-risk
// analyzer. SC-EX-007 keeps the ID of the former YAML rule so existing policy
// references continue to work after its implementation moves to structured
// script analysis.
func RuleMetadata() []rulemeta.Rule {
	return []rulemeta.Rule{
		{
			ID:       RulePythonDecodeExec,
			Name:     "Obfuscated Python payload execution",
			Severity: "CRITICAL",
			Category: "supply-chain-exfil",
			Analyzer: rulemeta.AnalyzerScriptRisk,
			Description: "Python code executes a value that is decoded, reconstructed from character codes, " +
				"or returned by a local decode helper. The analyzer binds exec/eval to base64, compression, " +
				"hexadecimal, codec, or chr-join construction instead of treating the operations as unrelated text.",
			Remediation: "Remove runtime payload construction and execution. Ship reviewable source code, verify its " +
				"integrity before use, and audit the environment for code run by the decoded payload.",
		},
		{
			ID:       RulePythonRemoteExec,
			Name:     "Remote Python payload execution",
			Severity: "CRITICAL",
			Category: "supply-chain-exfil",
			Analyzer: rulemeta.AnalyzerScriptRisk,
			Description: "Python code executes response content fetched through a bound requests, httpx, " +
				"or urllib client. The analyzer follows the response body through assignments and safe " +
				"transformations so a download and exec must form one flow.",
			Remediation: "Do not execute code fetched at runtime. Ship the source with the package, pin and " +
				"verify its integrity, and review any environment where the remote payload may have run.",
		},
		{
			ID:       RuleSystemPersistence,
			Name:     "Systemd or cron persistence installation",
			Severity: "CRITICAL",
			Category: "supply-chain-exfil",
			Analyzer: rulemeta.AnalyzerScriptRisk,
			Description: "Package or skill code installs a persistent systemd service/timer, cron entry, " +
				"or shell-profile payload. Structured pathlib paths and subprocess argv calls are resolved " +
				"so persistence split across ordinary Python expressions is still visible.",
			Remediation: "Do not install persistence mechanisms from package or skill code. Require an " +
				"explicit, documented administrative step and review the exact unit, schedule, or profile change.",
		},
		{
			ID:       RuleUnsafePipSource,
			Name:     "Unencrypted pip dependency source in a script",
			Severity: "MEDIUM",
			Category: "supply-chain",
			Analyzer: rulemeta.AnalyzerScriptRisk,
			Description: "A shell script runs pip against an unencrypted git source, package index, or artifact URL. " +
				"Because the source is executable package material, transport tampering can become code execution.",
			Remediation: "Use an authenticated HTTPS package index or git source, pin the dependency, and " +
				"verify hashes or signed provenance before installation.",
		},
		{
			ID:       RuleUnsafeNPMSource,
			Name:     "Unencrypted npm dependency source in a script",
			Severity: "MEDIUM",
			Category: "supply-chain",
			Analyzer: rulemeta.AnalyzerScriptRisk,
			Description: "A shell script runs npm install against an unencrypted git or package artifact URL. " +
				"Because installation consumes executable package material, transport tampering can become code execution.",
			Remediation: "Use an authenticated HTTPS registry, artifact, or git source, pin the dependency, and " +
				"verify its integrity before installation.",
		},
	}
}

var ruleInfo = rulemeta.Index(RuleMetadata())

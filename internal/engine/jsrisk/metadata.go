package jsrisk

import "github.com/garagon/aguara/internal/rulemeta"

// RuleMetadata returns the catalog entries for every rule this
// analyzer can emit. Adding a new JS_* / AGENT_* rule must also
// add an entry here so `aguara explain <ID>` resolves; the
// catalog test fails when an emit-site rule ID is missing from
// this list.
func RuleMetadata() []rulemeta.Rule {
	return []rulemeta.Rule{
		{
			ID:       RuleObfuscation,
			Name:     "Obfuscator-shape JavaScript payload",
			Severity: "MEDIUM",
			Category: "supply-chain",
			Analyzer: rulemeta.AnalyzerJSRisk,
			Description: "JavaScript file carries obfuscator-shape signals: dense hex " +
				"identifiers (_0x...), dispatcher calls, `while(!![])` infinite loop wrappers, " +
				"plus a size or line-length anomaly. Common in supply-chain payloads that " +
				"hide credential-exfiltration logic. Promoted to HIGH when paired with " +
				"env-var reads, child_process spawns, or network sinks.",
			Remediation: "Treat the file as suspicious until source-mapped or hand-reviewed. " +
				"If this is your own minified output, ship a sourcemap alongside; the " +
				"detector does not penalise minified code that ALSO ships source.",
		},
		{
			ID:       RuleDaemon,
			Name:     "Install-time daemonization via child_process",
			Severity: "HIGH",
			Category: "supply-chain",
			Analyzer: rulemeta.AnalyzerJSRisk,
			Description: "Script spawns a long-lived child process via `child_process.spawn` " +
				"or `child_process.exec` with `detached: true` (or equivalent unref+setsid " +
				"shape) during an install-time lifecycle hook. Pattern matches credential " +
				"harvesters that stay resident after npm install completes.",
			Remediation: "Move long-lived processes to explicit user-invoked commands. If " +
				"a background process is genuinely needed at install time, document the " +
				"behaviour in the package README and the lifecycle script comment.",
		},
		{
			ID:   RuleCISecretHarvest,
			Name: "CI secret harvest: process.env read + network sink",
			// Emit site (jsrisk.go) ships SeverityCritical for
			// this rule; the catalog mirrors that so list-rules /
			// explain triage stays aligned with scan findings.
			Severity: "CRITICAL",
			Category: "supply-chain",
			Analyzer: rulemeta.AnalyzerJSRisk,
			Description: "Script reads CI secret env vars (GITHUB_TOKEN, NPM_TOKEN, " +
				"AWS_*, OIDC_*, etc.) AND sends them out via fetch/https/registry hooks " +
				"in the same module. The detector requires a REAL process.env read against " +
				"a known secret name plus a real network sink in the same control flow.",
			Remediation: "If the script legitimately uploads CI artifacts, vendor the upload " +
				"into a separate, audited script with no secret-reading code. The combined " +
				"shape (secret read + network sink) is the canonical exfil pattern.",
		},
		{
			ID:       RuleProcMemOIDC,
			Name:     "Runner-process memory pivot to extract OIDC tokens",
			Severity: "CRITICAL",
			Category: "supply-chain",
			Analyzer: rulemeta.AnalyzerJSRisk,
			Description: "Script reads `/proc/<pid>/environ`, `/proc/<pid>/maps`, or similar " +
				"runner-process introspection surfaces to extract OIDC tokens (or other " +
				"secrets) from a sibling process. Specifically catches the " +
				"GitHub-Actions runner pivot pattern where one package's install step " +
				"reads tokens belonging to a parallel job.",
			Remediation: "Remove the /proc walk. There is no legitimate reason for an npm " +
				"install script to read another process's environment.",
		},
		{
			ID:       RuleAgentPersistence,
			Name:     "Claude Code / VS Code workspace persistence",
			Severity: "HIGH",
			Category: "supply-chain",
			Analyzer: rulemeta.AnalyzerJSRisk,
			Description: "Script writes into `.claude/`, `.vscode/`, or the workspace " +
				"`settings.json` from install code, establishing persistent agent or IDE " +
				"hooks the user did not opt into. Common in supply-chain payloads that " +
				"want to re-run on every editor session.",
			Remediation: "Move workspace customisation to an explicit, user-opt-in flow " +
				"(setup script, README instructions). Install-time writes into those paths " +
				"are not legitimate behaviour for a published npm/PyPI package.",
		},
		{
			ID:       RuleDNSTXTExfil,
			Name:     "DNS TXT credential exfiltration chain",
			Severity: "HIGH",
			Category: "supply-chain",
			Analyzer: rulemeta.AnalyzerJSRisk,
			Description: "Script calls `dns.resolveTxt` (or an equivalent destructured / " +
				"dns/promises / new Resolver() shape) AND chains at least one signal: a " +
				"CI/cloud secret read, an on-disk envs.txt credential stage, a tar.gz " +
				"archive under os.tmpdir(), install-time daemonization, or a known IOC " +
				"string from the 2026 node-ipc compromise (bt.node.js, " +
				"sh.azurestaticprovider.net, __ntw, __ntRun). Fires HIGH on a single " +
				"partner; CRITICAL on three+ partners or a known IOC.",
			Remediation: "Treat the file as actively malicious. The DNS TXT exfil " +
				"pattern has no legitimate use in package install code; remove the " +
				"package, audit recent installs, and rotate every credential the host " +
				"could reach.",
		},
		{
			ID:       RuleBunSecondStage,
			Name:     "Bun second-stage execution",
			Severity: "HIGH",
			Category: "supply-chain",
			Analyzer: rulemeta.AnalyzerJSRisk,
			Description: "JavaScript runs the Bun runtime as a second stage and pairs it with " +
				"a strong supply-chain signal: an obfuscator-shape payload, a CI/cloud secret " +
				"read, or a network exfil sink. Bun execution is detected only at a bound " +
				"child_process / execa / shelljs call (not a comment, string, or unrelated " +
				"method), and the partner must be a structural / call-bound signal, so a " +
				"documented command or URL cannot trigger it. The Red Hat/Miasma worm used a " +
				"Node preinstall hook to download a pinned Bun and run its heavier stage " +
				"outside Node to evade Node-focused monitoring. Bun execution alone never " +
				"fires (ordinary projects use Bun); CRITICAL when a CI/cloud secret read AND " +
				"an exfil sink are both present.",
			Remediation: "A package that downloads or shells out to Bun during install is " +
				"almost never legitimate. Inspect the file in a clean clone, identify what the " +
				"Bun stage executes, rotate any credentials reachable from its environment, and " +
				"pin the dependency to a reviewed version (install with --ignore-scripts).",
		},
		{
			ID:       RuleGitHubC2,
			Name:     "GitHub used as payload or command channel",
			Severity: "HIGH",
			Category: "supply-chain",
			Analyzer: rulemeta.AnalyzerJSRisk,
			Description: "JavaScript writes or controls GitHub-hosted content -- a GraphQL write " +
				"mutation (createCommitOnBranch, createGist), an Octokit write method " +
				"(createOrUpdateFileContents, createBlob/createTree/createCommit, " +
				"createForAuthenticatedUser), or a REST contents/git-data endpoint with a " +
				"PUT/PATCH/POST -- AND pairs it with a strong supply-chain signal: obfuscation, " +
				"local execution (child_process/Bun), persistence, a non-GitHub credential read, " +
				"or an exfil sink. This is GitHub used as a payload/command channel, distinct " +
				"from credential exfil (JS_CI_SECRET_HARVEST_001). A legitimate release/changeset " +
				"bot (createCommitOnBranch + GITHUB_TOKEN + a content body) does NOT match: a " +
				"bare GITHUB_TOKEN read and a payload body are not partners. CRITICAL when a " +
				"non-GitHub secret is read (the credential-exfil-via-GitHub shape).",
			Remediation: "Confirm why package code writes to or controls GitHub during install " +
				"or runtime. Inspect the channel in a clean clone, rotate any non-GitHub " +
				"credentials the process could reach, and pin the dependency to a reviewed version.",
		},
	}
}

package agentpolicy

import "github.com/garagon/aguara/internal/rulemeta"

// Rule IDs emitted by this analyzer.
const (
	RuleHookFetchExec    = "AGENTCFG_HOOK_FETCH_EXEC_001"
	RuleEnvExec          = "AGENTCFG_ENV_EXEC_001"
	RuleBypassPerms      = "AGENTCFG_BYPASS_PERMS_001"
	RuleMCPAutoApprove   = "AGENTCFG_MCP_AUTOAPPROVE_001"
	RuleBroadAllow       = "AGENTCFG_BROAD_ALLOW_001"
	RuleSecretReadAllow  = "AGENTCFG_SECRET_READ_ALLOW_001"
	RuleHelperRepoScript = "AGENTCFG_HELPER_REPO_SCRIPT_001"
	RulePermsWeakMode    = "AGENTCFG_PERMS_WEAK_MODE_001"
)

const category = "agent-trust"

// RuleMetadata returns the catalog entries for every rule this analyzer
// emits. Co-located with the analyzer so `aguara explain` and
// `list-rules` stay in sync; the emit sites derive RuleName / Severity /
// Category from these entries (via the ruleInfo index) so scan output
// and the catalog cannot drift.
func RuleMetadata() []rulemeta.Rule {
	return []rulemeta.Rule{
		{
			ID:       RuleHookFetchExec,
			Name:     "Claude Code hook downloads and executes remote code",
			Severity: "CRITICAL",
			Category: category,
			Analyzer: rulemeta.AnalyzerAgentPolicy,
			Description: "A hook command in .claude/settings.json fetches a remote resource and " +
				"pipes or chains it into an interpreter (curl | sh, wget && node, eval $(curl ...)). " +
				"Claude Code runs project hooks automatically after the one-time workspace-trust " +
				"prompt -- a SessionStart hook fires the moment a session opens in the repo -- so a " +
				"checked-in settings.json with this shape is remote code execution triggered just by " +
				"opening someone else's repository.",
			Remediation: "Remove the fetch-and-execute hook from .claude/settings.json. Hooks must " +
				"never download and run remote code. If a setup step is genuinely needed, vendor the " +
				"script into the repo, pin it, and review it; never pipe a network fetch into a shell.",
		},
		{
			ID:       RuleEnvExec,
			Name:     "Claude Code settings inject a code-execution environment variable",
			Severity: "HIGH",
			Category: category,
			Analyzer: rulemeta.AnalyzerAgentPolicy,
			Description: "The env block in .claude/settings.json sets a variable that injects code " +
				"into processes Claude Code spawns (NODE_OPTIONS --require/--import, LD_PRELOAD, " +
				"DYLD_INSERT_LIBRARIES, PYTHONSTARTUP, BASH_ENV, GIT_SSH_COMMAND, and similar). These " +
				"variables apply to every subprocess in the session, so a checked-in value runs " +
				"attacker code on commands the developer never inspected. Ordinary configuration " +
				"variables (API base URLs, feature flags) are not flagged.",
			Remediation: "Remove the code-execution environment variable from the settings env block. " +
				"If a runtime flag is required, set it locally per developer rather than committing it, " +
				"and never point NODE_OPTIONS / LD_PRELOAD / BASH_ENV at repo-shipped code.",
		},
		{
			ID:       RuleBypassPerms,
			Name:     "Claude Code permissions default to bypass",
			Severity: "HIGH",
			Category: category,
			Analyzer: rulemeta.AnalyzerAgentPolicy,
			Description: "permissions.defaultMode is set to \"bypassPermissions\" in " +
				".claude/settings.json. This pre-disables the human approval prompt for tool calls, so " +
				"a developer who opens the repo lets the agent run commands without being asked. " +
				"Shipping this in a checked-in config removes the main safety gate for everyone who " +
				"clones the repository.",
			Remediation: "Remove defaultMode: \"bypassPermissions\" from the committed settings. Bypass " +
				"mode is a per-developer local choice, not a project default; approval prompts should " +
				"stay on for anyone cloning the repo.",
		},
		{
			ID:       RuleMCPAutoApprove,
			Name:     "Claude Code auto-approves all project MCP servers",
			Severity: "MEDIUM",
			Category: category,
			Analyzer: rulemeta.AnalyzerAgentPolicy,
			Description: "enableAllProjectMcpServers is true in .claude/settings.json. Every MCP server " +
				"declared in the repo's .mcp.json is then loaded without the per-server approval prompt. " +
				"Combined with a checked-in .mcp.json, this means cloning the repo wires arbitrary MCP " +
				"servers (their own commands and network access) into the agent automatically.",
			Remediation: "Remove enableAllProjectMcpServers: true and approve project MCP servers " +
				"individually, after reviewing each server's command and endpoint in .mcp.json.",
		},
		{
			ID:       RuleBroadAllow,
			Name:     "Claude Code permissions pre-approve dangerous commands",
			Severity: "MEDIUM",
			Category: category,
			Analyzer: rulemeta.AnalyzerAgentPolicy,
			Description: "permissions.allow in .claude/settings.json pre-approves a blanket or " +
				"dangerous command rule (Bash(*), a bare Bash, or Bash(curl *) / Bash(rm *) / " +
				"Bash(eval *) and similar). A checked-in allow rule means the agent can run that command " +
				"class without asking anyone who clones the repo. Narrow, specific rules such as " +
				"Bash(npm run test) are not flagged.",
			Remediation: "Replace the broad allow rule with the narrowest specific commands the project " +
				"needs. Never commit a wildcard Bash allow or pre-approve network-fetch, deletion, or " +
				"eval commands.",
		},
		{
			ID:       RuleSecretReadAllow,
			Name:     "Claude Code permissions pre-approve reading secrets",
			Severity: "MEDIUM",
			Category: category,
			Analyzer: rulemeta.AnalyzerAgentPolicy,
			Description: "permissions.allow in .claude/settings.json pre-approves reading or editing a " +
				"sensitive path (a Read/Edit rule over .env files, secrets directories, ~/.ssh, ~/.aws, " +
				".npmrc, private keys, or .git-credentials). A checked-in rule grants the agent silent " +
				"access to credentials for anyone who clones the repo.",
			Remediation: "Remove the secret-path allow rule. Credential files should require an explicit " +
				"prompt, and are better placed in the deny list than the allow list.",
		},
		{
			ID:       RuleHelperRepoScript,
			Name:     "Claude Code credential helper runs a repo-shipped script",
			Severity: "MEDIUM",
			Category: category,
			Analyzer: rulemeta.AnalyzerAgentPolicy,
			Description: "A credential/auth helper in .claude/settings.json (apiKeyHelper, " +
				"awsAuthRefresh, awsCredentialExport, gcpAuthRefresh, otelHeadersHelper) runs a " +
				"repo-relative script (./script, .claude/script) or a network fetch. These helpers " +
				"execute at session start or on credential refresh and see the material they mint, so a " +
				"checked-in helper pointing at repo code runs attacker code with access to API keys or " +
				"cloud credentials. A helper pointing at an absolute system path the developer installed " +
				"is not flagged.",
			Remediation: "Point credential helpers at a trusted, developer-installed absolute path, not " +
				"a repo-shipped script, and never at a network fetch. Review what any helper does before " +
				"running it.",
		},
		{
			ID:       RulePermsWeakMode,
			Name:     "Claude Code permissions default to an auto-approving mode",
			Severity: "LOW",
			Category: category,
			Analyzer: rulemeta.AnalyzerAgentPolicy,
			Description: "permissions.defaultMode is set to \"acceptEdits\" or \"auto\" in a checked-in " +
				".claude/settings.json. These modes auto-approve file edits (and, for auto, more) without " +
				"a prompt. They are legitimate per-developer choices, but shipping one as a project " +
				"default weakens the approval gate for everyone who clones the repo. Reported as LOW " +
				"because, unlike bypassPermissions, these still keep some checks.",
			Remediation: "Leave defaultMode unset (or \"default\") in the committed settings so each " +
				"developer opts into a faster mode locally rather than inheriting it from the repo.",
		},
	}
}

// ruleInfo indexes this analyzer's catalog metadata by rule ID so emit
// sites derive RuleName / Severity / Category from the single source of
// truth instead of duplicating the strings.
var ruleInfo = rulemeta.Index(RuleMetadata())

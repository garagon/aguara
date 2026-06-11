package npmpolicy

import "github.com/garagon/aguara/internal/rulemeta"

// RuleMetadata returns the catalog entries for every rule this analyzer
// emits. Co-located with the analyzer so `aguara explain` and
// `list-rules` stay in sync with what scan actually reports. Severity
// and Category here MUST match the values the analyzer sets on each
// emitted Finding (locked by rulecatalog's metadata-match test).
func RuleMetadata() []rulemeta.Rule {
	return []rulemeta.Rule{
		{
			ID:       RuleDangerousAllScripts,
			Name:     "npm dangerously-allow-all-scripts enabled",
			Severity: "HIGH",
			Category: "supply-chain",
			Analyzer: rulemeta.AnalyzerNpmPolicy,
			Description: ".npmrc sets dangerously-allow-all-scripts=true, bypassing npm's " +
				"allowScripts policy entirely: every dependency install script (preinstall / " +
				"install / postinstall) runs regardless of whether it was approved or denied. " +
				"npm documents the flag as a migration escape hatch whose use is strongly " +
				"discouraged. Under the npm v12 trust model (dependency scripts blocked unless " +
				"approved), this single committed line re-opens the classic supply-chain " +
				"malware entry point for everyone who clones the repository.",
			Remediation: "Remove dangerously-allow-all-scripts from the committed .npmrc. Approve " +
				"the specific packages that genuinely need install scripts with `npm " +
				"approve-scripts <pkg>` (writing pinned allowScripts entries to package.json), " +
				"leaving everything else blocked.",
		},
		{
			ID:       RuleAllowScriptsUnpinned,
			Name:     "npm allowScripts approval not version-pinned",
			Severity: "MEDIUM",
			Category: "supply-chain",
			Analyzer: rulemeta.AnalyzerNpmPolicy,
			Description: "The allowScripts policy approves a package's install scripts by name " +
				"only (or .npmrc sets allow-scripts-pin=false, which makes `npm approve-scripts` " +
				"write such entries). A name-only `true` entry approves every future version of " +
				"the package, so a compromised release published tomorrow inherits the approval " +
				"that was granted to the version someone actually reviewed. npm's default is to " +
				"pin approvals as name@version. Name-only entries with value false are denies " +
				"(npm deny-scripts always writes them name-only) and are not flagged.",
			Remediation: "Re-approve with pinning enabled (the default): remove the name-only " +
				"entry and run `npm approve-scripts <pkg>` so the approval is written as " +
				"name@version, then re-review on version bumps. Remove allow-scripts-pin=false " +
				"from .npmrc if present.",
		},
		{
			ID:       RuleAllowGitRelaxed,
			Name:     "npm git-dependency resolution pinned open",
			Severity: "MEDIUM",
			Category: "supply-chain",
			Analyzer: rulemeta.AnalyzerNpmPolicy,
			Description: ".npmrc sets allow-git to \"all\" or \"root\", explicitly keeping git " +
				"dependency resolution enabled. npm v12 defaults allow-git to \"none\" because " +
				"resolving a git dependency is a code-execution path: the dependency's own " +
				".npmrc can override the git executable, which runs even under " +
				"--ignore-scripts. A committed value pins the relaxed behavior through the v12 " +
				"upgrade for everyone who clones (\"root\" bounds it to direct dependencies; " +
				"\"all\" includes transitive ones).",
			Remediation: "Remove allow-git from the committed .npmrc so the npm v12 default " +
				"(none) applies, or replace git dependencies with registry versions. If a git " +
				"dependency is genuinely required, prefer allow-git=root over all, and treat " +
				"the exception as a reviewed trust decision.",
		},
		{
			ID:       RuleAllowRemoteRelaxed,
			Name:     "npm remote-tarball resolution pinned open",
			Severity: "MEDIUM",
			Category: "supply-chain",
			Analyzer: rulemeta.AnalyzerNpmPolicy,
			Description: ".npmrc sets allow-remote to \"all\" or \"root\", explicitly keeping " +
				"remote-URL tarball resolution enabled. npm v12 defaults allow-remote to " +
				"\"none\": a tarball URL bypasses the registry's versioning, provenance, and " +
				"advisory surface entirely, so v12 makes consuming one an explicit decision. A " +
				"committed value pins the relaxed behavior through the upgrade (\"root\" bounds " +
				"it to direct dependencies; \"all\" includes transitive ones).",
			Remediation: "Remove allow-remote from the committed .npmrc so the npm v12 default " +
				"(none) applies, or replace URL tarball dependencies with registry versions. If " +
				"one is genuinely required, prefer allow-remote=root over all, and pin the " +
				"exact tarball.",
		},
	}
}

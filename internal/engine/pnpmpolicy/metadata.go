package pnpmpolicy

import "github.com/garagon/aguara/internal/rulemeta"

// RuleMetadata returns the catalog entries for every rule this analyzer
// emits. Co-located with the analyzer so `aguara explain` and
// `list-rules` stay in sync with what scan actually reports. Severity
// and Category here MUST match the values the analyzer sets on each
// emitted Finding (locked by rulecatalog's metadata-match test).
func RuleMetadata() []rulemeta.Rule {
	return []rulemeta.Rule{
		{
			ID:       RuleDangerousBuilds,
			Name:     "pnpm dangerouslyAllowAllBuilds enabled",
			Severity: "HIGH",
			Category: "supply-chain",
			Analyzer: rulemeta.AnalyzerPnpmPolicy,
			Description: "pnpm-workspace.yaml sets dangerouslyAllowAllBuilds: true. This lets " +
				"every dependency, direct or transitive, run install-time lifecycle scripts " +
				"(preinstall / install / postinstall) without approval. It is the classic " +
				"supply-chain malware entry point that pnpm's build-approval model exists to " +
				"close, re-opened by a single flag.",
			Remediation: "Remove dangerouslyAllowAllBuilds: true. Approve the specific packages " +
				"that genuinely need to run build scripts via allowBuilds (or `pnpm approve-builds`), " +
				"leaving everything else unable to execute install-time code.",
		},
		{
			ID:       RuleStrictDepBuildsDisabled,
			Name:     "pnpm strictDepBuilds disabled",
			Severity: "MEDIUM",
			Category: "supply-chain",
			Analyzer: rulemeta.AnalyzerPnpmPolicy,
			Description: "pnpm-workspace.yaml sets strictDepBuilds: false (the v11 default is true). " +
				"With strict dep builds off, a dependency that wants to run an unapproved build " +
				"script produces a warning instead of failing the install, so unreviewed " +
				"install-time code can slip through CI unnoticed.",
			Remediation: "Remove strictDepBuilds: false (or set it to true) so an unapproved build " +
				"script fails the install and forces an explicit allowBuilds decision.",
		},
		{
			ID:       RuleExoticSubdepsDisabled,
			Name:     "pnpm blockExoticSubdeps disabled",
			Severity: "MEDIUM",
			Category: "supply-chain",
			Analyzer: rulemeta.AnalyzerPnpmPolicy,
			Description: "pnpm-workspace.yaml sets blockExoticSubdeps: false (the v11 default is true). " +
				"This allows transitive dependencies to be resolved from exotic sources (direct git " +
				"URLs, tarball URLs) rather than the registry, widening the set of code that can " +
				"enter the dependency tree without registry-level provenance.",
			Remediation: "Remove blockExoticSubdeps: false (or set it to true) so transitive " +
				"dependencies must come from the configured registry. If a specific exotic subdep " +
				"is required, vet it and pin it explicitly rather than disabling the block globally.",
		},
		{
			ID:       RuleTrustLockfile,
			Name:     "pnpm trustLockfile enabled",
			Severity: "MEDIUM",
			Category: "supply-chain",
			Analyzer: rulemeta.AnalyzerPnpmPolicy,
			Description: "pnpm-workspace.yaml sets trustLockfile: true. pnpm then stops re-applying " +
				"minimumReleaseAge and trustPolicy to entries already present in the loaded lockfile. " +
				"In a closed repo this can be acceptable, but on an open-source project or any repo " +
				"that takes outside contributions it raises the risk of lockfile poisoning, since a " +
				"tampered lockfile entry skips supply-chain verification.",
			Remediation: "Remove trustLockfile: true so pnpm keeps verifying lockfile entries against " +
				"minimumReleaseAge and trustPolicy. Only consider enabling it in fully closed repos " +
				"where the lockfile is trusted end to end.",
		},
		{
			ID:       RuleMinReleaseAgeDisabled,
			Name:     "pnpm minimumReleaseAge disabled",
			Severity: "LOW",
			Category: "supply-chain",
			Analyzer: rulemeta.AnalyzerPnpmPolicy,
			Description: "pnpm-workspace.yaml sets minimumReleaseAge: 0, an explicit opt-out of the " +
				"v11 default (1440 minutes). The release-age window blunts attacks that rely on a " +
				"freshly published malicious version being installed within minutes; setting it to 0 " +
				"removes that delay entirely.",
			Remediation: "Remove minimumReleaseAge: 0 to fall back to the default window, or set a " +
				"positive value (e.g. 1440 for one day) so newly published versions are not installed " +
				"immediately.",
		},
		{
			ID:       RuleMinReleaseAgeNonStrict,
			Name:     "pnpm minimumReleaseAge not strictly enforced",
			Severity: "LOW",
			Category: "supply-chain",
			Analyzer: rulemeta.AnalyzerPnpmPolicy,
			Description: "pnpm-workspace.yaml configures minimumReleaseAge with a positive value but " +
				"also sets minimumReleaseAgeStrict: false. Non-strict mode lets pnpm fall back to a " +
				"version that does not meet the age threshold when no compatible alternative exists, " +
				"so the release-age protection can be silently bypassed.",
			Remediation: "Set minimumReleaseAgeStrict: true (or remove the false override) so the " +
				"release-age threshold is always enforced. Resolve version conflicts by pinning a " +
				"compatible aged version rather than allowing a fresh fallback.",
		},
		{
			ID:       RuleTrustPolicyOff,
			Name:     "pnpm trustPolicy explicitly off",
			Severity: "LOW",
			Category: "supply-chain",
			Analyzer: rulemeta.AnalyzerPnpmPolicy,
			Description: "pnpm-workspace.yaml explicitly sets trustPolicy: off. While off is the " +
				"current built-in default, configuring it explicitly opts the project out of trust " +
				"evidence checks (such as no-downgrade) that harden the lockfile against tampering. " +
				"The analyzer only flags the explicit setting, never its absence.",
			Remediation: "Consider a stricter trust policy such as no-downgrade, which blocks " +
				"downgrades of trust evidence. If off is intentional, document why; the finding only " +
				"surfaces because the opt-out is explicit.",
		},
		{
			ID:       RuleLegacyBuildPolicy,
			Name:     "pnpm legacy v10 build-policy setting",
			Severity: "INFO",
			Category: "supply-chain",
			Analyzer: rulemeta.AnalyzerPnpmPolicy,
			Description: "pnpm-workspace.yaml uses a build-policy setting that pnpm v10 honored but " +
				"v11 removed or replaced (onlyBuiltDependencies, neverBuiltDependencies, " +
				"ignoredBuiltDependencies, ignoreDepScripts, onlyBuiltDependenciesFile). On v11 the " +
				"setting no longer takes effect, so the intended build restriction may silently not " +
				"apply. This is a migration nudge, not a vulnerability.",
			Remediation: "Migrate the legacy setting to allowBuilds, which is the v11 mechanism for " +
				"deciding which dependencies may run build scripts. Verify the resulting policy " +
				"matches the original intent.",
		},
		{
			ID:       RuleBuildApprovalPending,
			Name:     "pnpm allowBuilds entry pending decision",
			Severity: "MEDIUM",
			Category: "supply-chain",
			Analyzer: rulemeta.AnalyzerPnpmPolicy,
			Description: "pnpm-workspace.yaml has an allowBuilds entry with no explicit true/false " +
				"decision (a null/empty placeholder). pnpm adds such placeholders for dependencies " +
				"with build scripts so a human can decide whether to allow them; an undecided entry " +
				"means a build script is still pending review.",
			Remediation: "Set each placeholder allowBuilds entry to true (allow the build script) or " +
				"false (block it) after reviewing what the package's install-time script does. Run " +
				"`pnpm approve-builds` to make the decision interactively.",
		},
	}
}

// ruleInfo indexes this analyzer's catalog metadata by rule ID so emit
// sites derive RuleName / Severity / Category from the single source of
// truth instead of duplicating the strings.
var ruleInfo = rulemeta.Index(RuleMetadata())

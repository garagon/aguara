package pkgmeta

import "github.com/garagon/aguara/internal/rulemeta"

// RuleMetadata returns the catalog entries for every rule this
// analyzer can emit. Co-located with the analyzer so adding a new
// NPM_* rule keeps the catalog and the emitter in sync.
func RuleMetadata() []rulemeta.Rule {
	return []rulemeta.Rule{
		{
			ID:       RuleLifecycleGit,
			Name:     "npm install-time lifecycle script with git-sourced dependency",
			Severity: "HIGH",
			Category: "supply-chain",
			Analyzer: rulemeta.AnalyzerPkgMeta,
			Description: "package.json declares an install-time lifecycle script " +
				"(preinstall, install, postinstall, prepublish, preprepare, prepare, " +
				"postprepare) AND at least one dependency sourced from git (`git+`, " +
				"`git://`, `git@`, `github:`). The combination lets a git ref the author " +
				"controls execute arbitrary code on every install, bypassing npm's " +
				"signature surface. Promoted to CRITICAL when the dep is in " +
				"`optionalDependencies` AND carries a suspicious name (typosquat shape).",
			Remediation: "Pin the dependency to a published npm version with a signed " +
				"tarball. If the git dep is unavoidable, drop the install-time lifecycle " +
				"script and run the equivalent work in a vetted CI step instead.",
		},
		{
			ID:       RuleOptionalGit,
			Name:     "git-sourced optionalDependency",
			Severity: "MEDIUM",
			Category: "supply-chain",
			Analyzer: rulemeta.AnalyzerPkgMeta,
			Description: "package.json declares a git-sourced `optionalDependency`. " +
				"`optionalDependencies` install silently on every host where they resolve, " +
				"so a git ref the author controls becomes a stealthy install vector. " +
				"Promoted to HIGH when the package name has a typosquat shape. Suppressed " +
				"when NPM_LIFECYCLE_GIT_001 already covers the same dependency.",
			Remediation: "Pin to a published npm version with a signed tarball, or make " +
				"the dependency mandatory so its install behaviour is auditable.",
		},
		{
			ID:       RulePublishSurface,
			Name:     "publishConfig + install/build/test + trusted publishing reference",
			Severity: "HIGH",
			Category: "supply-chain",
			Analyzer: rulemeta.AnalyzerPkgMeta,
			Description: "package.json carries a `publishConfig` (or publish script) " +
				"alongside install/build/test scripts AND a value-aware reference to " +
				"trusted publishing (provenance, signed-publishes). The combined surface " +
				"means an attacker who controls an install-time script can mint signed " +
				"releases on the project's behalf.",
			Remediation: "Move the publish surface into a separate package (or a separate " +
				"CI job) that does not execute install/build/test scripts. Trusted " +
				"publishing should only run from a vetted, minimal-scope environment.",
		},
	}
}

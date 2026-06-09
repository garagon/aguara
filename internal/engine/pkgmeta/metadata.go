package pkgmeta

import "github.com/garagon/aguara/internal/rulemeta"

// RuleMetadata returns the catalog entries for every rule this
// analyzer can emit. Co-located with the analyzer so adding a new
// NPM_* rule keeps the catalog and the emitter in sync.
func RuleMetadata() []rulemeta.Rule {
	return []rulemeta.Rule{
		{
			ID:       RuleLifecycleGit,
			Name:     "Git dependency can execute lifecycle code during install",
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
			Name:     "Optional dependency resolves executable code from git",
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
			ID:       RuleLocalJSLifecycle,
			Name:     "npm lifecycle script executes local JavaScript",
			Severity: "HIGH",
			Category: "supply-chain",
			Analyzer: rulemeta.AnalyzerPkgMeta,
			Description: "package.json defines an install-time lifecycle script (preinstall, " +
				"install, postinstall, preprepare, prepare, postprepare, prepublish, prepack, " +
				"postpack) whose body runs Node or Bun on local JavaScript: node index.js, " +
				"node ./scripts/setup.mjs, node -e/--eval, bun run x, or bun ./setup.mjs. npm " +
				"runs these hooks automatically on install, so executing the package's own JS " +
				"is the first hop of supply-chain droppers like the Red Hat/Miasma worm, which " +
				"shipped a preinstall hook running node index.js. Detection walks the parsed " +
				"scripts object, so a same-named key elsewhere in the manifest and brace-bearing " +
				"shell expansions in sibling scripts do not cause a false positive or a miss.",
			Remediation: "Install-time code execution should be unnecessary for most packages. " +
				"Read the referenced script in a clean clone before installing, prefer packages " +
				"with no install/preinstall/postinstall hooks, pin the dependency to a reviewed " +
				"version, and install with --ignore-scripts where possible.",
		},
		{
			ID:       RulePublishSurface,
			Name:     "Package publish surface exposed to install-time code",
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

// ruleInfo indexes this analyzer's catalog metadata by rule ID so emit
// sites derive RuleName / Severity / Category from the single source of
// truth instead of duplicating the strings.
var ruleInfo = rulemeta.Index(RuleMetadata())

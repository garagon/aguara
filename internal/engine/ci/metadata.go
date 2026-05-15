package ci

import "github.com/garagon/aguara/internal/rulemeta"

// RuleMetadata returns the catalog entries for every rule this
// analyzer can emit. Co-located with the analyzer so an engineer
// adding a new GHA_* rule cannot forget the explain entry -- both
// live in the same package.
func RuleMetadata() []rulemeta.Rule {
	return []rulemeta.Rule{
		{
			ID:       RulePwnRequest,
			Name:     "Pull-request-target with PR-controlled checkout",
			Severity: "HIGH",
			Category: "supply-chain",
			Analyzer: rulemeta.AnalyzerCITrust,
			Description: "GitHub Actions workflow triggered on `pull_request_target` " +
				"that checks out PR-controlled code and runs install/build/test/interpreter " +
				"steps in the same job. The `pull_request_target` trigger runs with the " +
				"repository's secrets in scope, so untrusted PR code gains access to write " +
				"tokens. Promoted to CRITICAL when the workflow also grants `contents: write` " +
				"or similar write permissions.",
			Remediation: "Use `pull_request` instead, or split the workflow so the " +
				"`pull_request_target` job never executes PR-controlled code (no install/" +
				"build/test/interpreter steps after the checkout). If write permissions are " +
				"needed, gate them behind a manual review (`environment:` with required " +
				"reviewers) rather than firing automatically on every PR.",
		},
		{
			ID:       RuleCache,
			Name:     "Pull-request-target cache poisoning chain",
			Severity: "HIGH",
			Category: "supply-chain",
			Analyzer: rulemeta.AnalyzerCITrust,
			Description: "Same `pull_request_target` + PR-controlled checkout chain as " +
				"GHA_PWN_REQUEST_001, additionally combined with an `actions/cache` write. " +
				"PR-controlled code can populate the cache so subsequent runs (including on " +
				"trusted branches) restore attacker-controlled artifacts. Promoted to " +
				"CRITICAL when paired with code execution.",
			Remediation: "Disable cache writes on PR-triggered jobs (`actions/cache/restore` " +
				"is read-only) or scope the cache key to the PR's head SHA so cross-PR " +
				"poisoning cannot land on `main`.",
		},
		{
			ID:       RuleOIDC,
			Name:     "OIDC token grant on install/build/test chain",
			Severity: "HIGH",
			Category: "supply-chain",
			Analyzer: rulemeta.AnalyzerCITrust,
			Description: "Workflow grants `id-token: write` to a job that ALSO runs " +
				"install/build/test steps. The OIDC token federates to cloud roles and " +
				"trusted-publishing surfaces; pairing it with arbitrary install-time code " +
				"execution lets a compromised dependency mint cloud credentials. Promoted " +
				"to CRITICAL when the job also publishes (npm, PyPI, Docker, ...).",
			Remediation: "Split the workflow: publish steps and id-token grants run in a " +
				"separate job that does not execute install/build/test commands. The " +
				"install job stays untrusted; the publish job receives a small, vetted " +
				"artifact.",
		},
		{
			ID:       RuleCheckout,
			Name:     "Pull-request-target head-ref checkout without persist-credentials: false",
			Severity: "HIGH",
			Category: "supply-chain",
			Analyzer: rulemeta.AnalyzerCITrust,
			Description: "Workflow uses `actions/checkout` against the PR head ref on a " +
				"`pull_request_target` trigger without setting `persist-credentials: false`. " +
				"The default behaviour leaves the workflow's GITHUB_TOKEN in the local git " +
				"config, so any subsequent step (or PR-controlled hook) can push back to the " +
				"repository.",
			Remediation: "Add `with: persist-credentials: false` to the checkout step, or " +
				"switch the trigger to `pull_request` (which runs without write tokens).",
		},
	}
}

package pyrisk

import "github.com/garagon/aguara/internal/rulemeta"

// RuleMetadata returns the catalog entry for the rule this analyzer
// emits. Co-located with the analyzer so `aguara explain` and
// `list-rules` stay in sync with the emitter. The ID is unchanged from
// the retired YAML rule; only the detection moved from co-presence to a
// real fetch->eval binding.
func RuleMetadata() []rulemeta.Rule {
	return []rulemeta.Rule{
		{
			ID:       RulePyImportTimeRemoteJS,
			Name:     "PyPI import-time remote JavaScript execution",
			Severity: "CRITICAL",
			Category: "supply-chain",
			Analyzer: rulemeta.AnalyzerPyRisk,
			Description: "A Python package that, at install or import time " +
				"(setup.py / __init__.py), downloads remote JavaScript and runs it " +
				"through Node. This is the TrapDoor-style PyPI payload. The analyzer " +
				"binds the two halves: the value passed to `node -e` / `--eval` must " +
				"trace back, in one or two simple assignment hops, to a remote fetch of " +
				"a JavaScript payload (requests/httpx/urllib reading a .js URL or the " +
				"campaign host). An unrelated `node -e`, a `node build.js`, or a fetched " +
				"config.json does not trip it.",
			Remediation: "Remove the remote fetch and Node execution from package " +
				"import/setup code. Packages must never download and run remote code at " +
				"install or import time. Audit the host for credential exposure and " +
				"rotate any tokens reachable from the build or import environment.",
		},
	}
}

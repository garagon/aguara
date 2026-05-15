// Package rulemeta is the single source of truth for "a rule the
// user can explain or list". It defines a neutral Rule type that
// every catalog source -- YAML-compiled pattern rules, --rules dir
// custom rules, and analyzer-emitted rules (jsrisk, ci-trust,
// pkgmeta, toxicflow, nlp-injection) -- conforms to.
//
// Keeping this surface independent of internal/rules.CompiledRule
// and the various analyzer-internal rule types means:
//
//   - The CLI (explain, list-rules) can show every rule the scanner
//     might emit, not just the YAML subset.
//   - The Go API (aguara.ListRules / aguara.ExplainRule) returns a
//     consistent shape regardless of which subsystem owns the rule.
//   - New analyzer rules become explainable by adding a single
//     RuleMetadata() entry in the analyzer package -- no plumbing
//     through the YAML compile path.
//
// Patterns, TruePositives, FalsePositives are optional. Analyzer-
// emitted rules carry no patterns because the analyzer logic itself
// is the "pattern"; YAML rules carry concrete regex/contains
// strings.
package rulemeta

// Rule is the neutral metadata shape for a detection rule.
//
// Field semantics:
//
//   - ID is the canonical rule identifier (e.g. "JS_DNS_TXT_EXFIL_001",
//     "PROMPT_INJECTION_004"). Always upper-case, ASCII-only.
//   - Analyzer names the engine that emits the rule. Empty for
//     pattern-matcher rules driven by YAML; set for analyzer-owned
//     rules ("ci-trust", "pkgmeta", "jsrisk", "nlp", "toxicflow").
//     The empty case stays empty in JSON output (omitempty).
//   - Severity is the canonical string ("CRITICAL", "HIGH", ...),
//     matching what the scanner emits in findings.
//   - Patterns is empty for analyzer rules -- the analyzer logic
//     IS the pattern. YAML rules emit a "[regex] ..." / "[contains]
//     ..." description per pattern.
//   - TruePositives / FalsePositives are the YAML rules' self-test
//     examples. Analyzer rules can include hand-curated fixtures
//     here when useful, or leave them empty.
type Rule struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Severity       string   `json:"severity"`
	Category       string   `json:"category"`
	Analyzer       string   `json:"analyzer,omitempty"`
	Description    string   `json:"description,omitempty"`
	Remediation    string   `json:"remediation,omitempty"`
	Patterns       []string `json:"patterns,omitempty"`
	TruePositives  []string `json:"true_positives,omitempty"`
	FalsePositives []string `json:"false_positives,omitempty"`
}

// Analyzer name constants. Centralised here so a typo in one place
// cannot make a record undiscoverable. The values are user-visible
// (they show up in JSON output and in --filter args), so they're
// short, lower-case, kebab-stable.
const (
	AnalyzerCITrust   = "ci-trust"
	AnalyzerPkgMeta   = "pkgmeta"
	AnalyzerJSRisk    = "jsrisk"
	AnalyzerNLP       = "nlp"
	AnalyzerToxicFlow = "toxicflow"
	AnalyzerRugPull   = "rugpull"
	AnalyzerPattern   = "" // YAML-driven rules; empty so JSON omits the field
)

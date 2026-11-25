package types

// ToolInfo identifies the Aguara build that produced a report.
type ToolInfo struct {
	// Name is always "aguara".
	Name string `json:"name"`
	// Version is the release version (for example "v0.29.0"), "dev" for
	// an unversioned build, or the Go module version when Aguara is used
	// as a library.
	Version string `json:"version"`
	// Commit is the source commit the binary was built from, when known.
	Commit string `json:"commit,omitempty"`
}

// CatalogInfo identifies the rule catalog a scan used, so consumers can
// tell whether two reports were produced with the same rules.
type CatalogInfo struct {
	// Detections is the number of rules in the catalog: pattern rules plus
	// analyzer-emitted rules, after disabled rules are removed. It matches
	// the length of `aguara list-rules` with the same rule options.
	Detections int `json:"detections"`
	// PatternRules is the number of compiled YAML pattern rules (built-in
	// and custom), the value scan results report as rules_loaded.
	PatternRules int `json:"pattern_rules"`
	// AnalyzerRules is the number of analyzer-emitted rules.
	AnalyzerRules int `json:"analyzer_rules"`
	// Digest is "sha256:" and the hex SHA-256 of the canonical catalog:
	// every rule's ID, name, severity, category, analyzer, description,
	// remediation and CWE list, and for pattern rules their targets, match
	// mode, line window, sensitivity, patterns and exclude patterns. It
	// changes whenever a rule is added, removed, disabled, re-rated or
	// edited. Analyzer logic is identified by the tool version, not by
	// the digest.
	Digest string `json:"digest"`
}

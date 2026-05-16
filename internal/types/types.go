// Package types defines shared data structures (Finding, Severity, ScanResult)
// used across scanner, meta, and engine packages to prevent import cycles.
package types

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Severity represents the severity level of a finding.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "CRITICAL"
	case SeverityHigh:
		return "HIGH"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityLow:
		return "LOW"
	case SeverityInfo:
		return "INFO"
	default:
		return "UNKNOWN"
	}
}

// ParseSeverity converts a string to a Severity level.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return SeverityCritical, nil
	case "HIGH":
		return SeverityHigh, nil
	case "MEDIUM":
		return SeverityMedium, nil
	case "LOW":
		return SeverityLow, nil
	case "INFO":
		return SeverityInfo, nil
	default:
		return SeverityInfo, fmt.Errorf("unknown severity: %q", s)
	}
}

// ContextLine represents a line of source code around a finding.
type ContextLine struct {
	Line    int    `json:"line"`
	Content string `json:"content"`
	IsMatch bool   `json:"is_match"`
}

// ExtractContext returns lines surrounding lineNum (1-based) as ContextLine slice.
// before/after control how many lines to include above and below the match.
func ExtractContext(lines []string, lineNum, before, after int) []ContextLine {
	var ctx []ContextLine
	start := max(lineNum-before-1, 0)
	end := min(lineNum+after, len(lines))
	for i := start; i < end; i++ {
		ctx = append(ctx, ContextLine{
			Line:    i + 1,
			Content: lines[i],
			IsMatch: i+1 == lineNum,
		})
	}
	return ctx
}

// Finding represents a single security finding.
type Finding struct {
	RuleID      string        `json:"rule_id"`
	RuleName    string        `json:"rule_name"`
	Severity    Severity      `json:"severity"`
	Category    string        `json:"category"`
	Description string        `json:"description,omitempty"`
	FilePath    string        `json:"file_path"`
	Line        int           `json:"line"`
	Column      int           `json:"column,omitempty"`
	MatchedText string        `json:"matched_text"`
	Context     []ContextLine `json:"context,omitempty"`
	Score       float64       `json:"score,omitempty"`
	Confidence  float64       `json:"confidence,omitempty"`
	Remediation string        `json:"remediation,omitempty"`
	Analyzer    string        `json:"analyzer"`
	InCodeBlock bool          `json:"in_code_block,omitempty"`
	// Sensitive marks findings whose MatchedText / matching context line is
	// expected to capture a real secret value (a credential read combined
	// with a transmission verb, a cred+exfil NLP combo, a toxic-flow pair
	// rooted in private-data access). RedactSensitiveFindings scrubs these
	// before they reach JSON, SARIF, or terminal output so the scanner does
	// not create a second copy of the secret in CI logs or uploaded
	// artifacts. The flag is independent of Category so a rule outside the
	// "credential-leak" category (MCP_007, NLP_CRED_EXFIL_COMBO, TOXIC_*
	// cred-bound) can still opt into redaction.
	Sensitive bool `json:"sensitive,omitempty"`
}

// RedactedPlaceholder is the value that replaces matched text and matching
// context lines for findings whose raw match would leak a secret. Kept as a
// stable string so JSON/SARIF consumers can grep for it consistently.
const RedactedPlaceholder = "[REDACTED]"

// RedactSensitiveFindings scrubs matched text and context lines for findings
// that are known to carry a real secret value: either the rule / analyzer set
// Sensitive == true, or the legacy category-based contract
// (Category == "credential-leak") still applies. Other findings are left
// intact because their match is typically a pattern signature rather than a
// secret.
//
// Context redaction differs by source. Analyzer-emitted Sensitive findings
// (nlp-injection, toxicflow, toxicflow-crossfile) treat their entire Context
// window as secret-bearing because their MatchedText is a multi-line section
// / file blob — the secret can sit on a non-IsMatch context line. Single-
// line Sensitive findings (pattern matcher) and the legacy credential-leak
// category scrub only the IsMatch line so the surrounding-line view used by
// reviewers stays intact.
//
// The category fallback exists so custom rules authored before the Sensitive
// flag existed keep redacting — dropping it would silently regress every user
// who relied on category == "credential-leak" to gate redaction.
//
// A second pass scrubs sensitive lines across every finding's Context. Two
// findings can share a Context window (a credential-leak hit on line 5 + a
// prompt-injection hit on line 7 both pull lines 2-10 via ExtractContext);
// without the second pass the prompt-injection finding would still serialize
// the line 5 secret even though the credential-leak finding got redacted.
func RedactSensitiveFindings(findings []Finding) {
	// Pass 1: redact each Sensitive / credential-leak finding's own
	// MatchedText + Context, and record which (FilePath, Line) tuples
	// are now considered secret-bearing.
	type fileLine struct {
		path string
		line int
	}
	sensitiveLines := make(map[fileLine]bool)
	for i := range findings {
		isSensitive := findings[i].Sensitive
		isLegacyCred := findings[i].Category == "credential-leak"
		if !isSensitive && !isLegacyCred {
			continue
		}
		findings[i].MatchedText = RedactedPlaceholder
		multiLine := isSensitive && multiLineAnalyzers[findings[i].Analyzer]
		for j := range findings[i].Context {
			cl := &findings[i].Context[j]
			if multiLine {
				// Analyzer findings span multiple source lines; the
				// secret may sit on a non-IsMatch context line, so
				// scrub the whole block AND mark every line in the
				// window for cross-finding redaction.
				cl.Content = RedactedPlaceholder
				sensitiveLines[fileLine{findings[i].FilePath, cl.Line}] = true
				continue
			}
			if cl.IsMatch {
				cl.Content = RedactedPlaceholder
				sensitiveLines[fileLine{findings[i].FilePath, cl.Line}] = true
			}
		}
	}

	if len(sensitiveLines) == 0 {
		return
	}

	// Pass 2: for every finding (including non-sensitive ones), scrub
	// Context lines whose (FilePath, Line) was marked sensitive in pass 1.
	for i := range findings {
		for j := range findings[i].Context {
			cl := &findings[i].Context[j]
			if sensitiveLines[fileLine{findings[i].FilePath, cl.Line}] {
				cl.Content = RedactedPlaceholder
			}
		}
	}
}

// multiLineAnalyzers names the analyzers whose emitted Finding's MatchedText
// is a multi-line section / file blob rather than a single-line regex hit.
// For these, the secret can sit on any line in the Context window, not just
// the IsMatch one, so RedactSensitiveFindings widens the per-finding scrub
// and the cross-finding sensitive-line set.
var multiLineAnalyzers = map[string]bool{
	"nlp-injection":       true,
	"toxicflow":           true,
	"toxicflow-crossfile": true,
}

// RedactCredentialFindings is the previous name of RedactSensitiveFindings,
// kept as an alias so library consumers pinned to the old API keep compiling.
//
// Deprecated: use RedactSensitiveFindings. Behaviour is identical — the new
// name also covers findings flagged Sensitive == true by rules or analyzers
// outside the "credential-leak" category.
func RedactCredentialFindings(findings []Finding) {
	RedactSensitiveFindings(findings)
}

// DowngradeSeverity drops severity by one level, flooring at LOW.
// INFO is left unchanged (it's a different class, not part of the severity ladder).
func DowngradeSeverity(sev Severity) Severity {
	switch sev {
	case SeverityCritical:
		return SeverityHigh
	case SeverityHigh:
		return SeverityMedium
	case SeverityMedium:
		return SeverityLow
	default:
		return sev
	}
}

// ScanProfile controls how aggressively findings are enforced.
type ScanProfile int

const (
	// ProfileStrict enforces all rules (default for standalone scanning).
	ProfileStrict ScanProfile = iota
	// ProfileContentAware only enforces MinimalEnforceRules; everything else
	// is downgraded to clean. Use for content/file-editing tools.
	ProfileContentAware
	// ProfileMinimal only enforces MinimalEnforceRules as flags; everything
	// else is downgraded to clean. Use for trusted internal agents.
	ProfileMinimal
)

// DeduplicateMode controls how findings are deduplicated.
type DeduplicateMode int

const (
	// DeduplicateFull removes same-rule AND cross-rule duplicates per line (default, CLI behavior).
	DeduplicateFull DeduplicateMode = iota
	// DeduplicateSameRuleOnly removes same-rule duplicates but keeps cross-rule findings on same line.
	DeduplicateSameRuleOnly
)

// Verdict represents the final policy decision after all filtering layers.
type Verdict int

const (
	// VerdictClean means no actionable findings.
	VerdictClean Verdict = iota
	// VerdictFlag means findings are informational only (not blocking).
	VerdictFlag
	// VerdictBlock means findings require action (blocking).
	VerdictBlock
)

func (v Verdict) String() string {
	switch v {
	case VerdictClean:
		return "clean"
	case VerdictFlag:
		return "flag"
	case VerdictBlock:
		return "block"
	default:
		return "unknown"
	}
}

// ScanResult holds the complete results of a scan.
type ScanResult struct {
	Findings     []Finding     `json:"findings"`
	FilesScanned int           `json:"files_scanned"`
	RulesLoaded  int           `json:"rules_loaded"`
	Verdict      Verdict       `json:"verdict"`
	RiskScore    float64       `json:"risk_score"`
	ToolName     string        `json:"tool_name,omitempty"`
	Duration     time.Duration `json:"-"`
	Target       string        `json:"-"`
}

// MarshalJSON implements custom JSON marshaling so Duration serializes
// as milliseconds, and normalizes the empty-results shape so consumers
// always see `"findings": []` instead of `"findings": null` on clean
// scans. The normalization covers every ScanResult producer (the
// Scanner, the CLI's aggregate runAutoScan, library callers that
// construct results directly) without each one needing to remember
// the contract.
func (r ScanResult) MarshalJSON() ([]byte, error) {
	if r.Findings == nil {
		r.Findings = []Finding{}
	}
	type Alias ScanResult
	return json.Marshal(struct {
		Alias
		DurationMS int64 `json:"duration_ms"`
	}{
		Alias:      Alias(r),
		DurationMS: r.Duration.Milliseconds(),
	})
}

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
}

// RedactedPlaceholder is the value that replaces matched text and matching
// context lines for findings whose raw match would leak a secret. Kept as a
// stable string so JSON/SARIF consumers can grep for it consistently.
const RedactedPlaceholder = "[REDACTED]"

// RedactCredentialFindings scrubs matched text and matching context lines for
// findings in the credential-leak category so that detecting a secret does not
// create a second copy of the secret in scan output, CI logs, or SARIF
// artifacts uploaded to GitHub Code Scanning.
//
// Only findings with Category == "credential-leak" are modified. Other
// categories are left intact because their match is typically a pattern
// signature rather than a secret.
func RedactCredentialFindings(findings []Finding) {
	for i := range findings {
		if findings[i].Category != "credential-leak" {
			continue
		}
		findings[i].MatchedText = RedactedPlaceholder
		for j := range findings[i].Context {
			if findings[i].Context[j].IsMatch {
				findings[i].Context[j].Content = RedactedPlaceholder
			}
		}
	}
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

// MarshalJSON implements custom JSON marshaling so Duration serializes as milliseconds.
func (r ScanResult) MarshalJSON() ([]byte, error) {
	type Alias ScanResult
	return json.Marshal(struct {
		Alias
		DurationMS int64 `json:"duration_ms"`
	}{
		Alias:      Alias(r),
		DurationMS: r.Duration.Milliseconds(),
	})
}

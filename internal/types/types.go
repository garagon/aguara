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
	Analyzer    string        `json:"analyzer"`
	InCodeBlock bool          `json:"in_code_block,omitempty"`
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

// ScanResult holds the complete results of a scan.
type ScanResult struct {
	Findings     []Finding     `json:"findings"`
	FilesScanned int           `json:"files_scanned"`
	RulesLoaded  int           `json:"rules_loaded"`
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

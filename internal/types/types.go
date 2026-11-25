// Package types defines shared data structures (Finding, Severity, ScanResult)
// used across scanner, meta, and engine packages to prevent import cycles.
package types

import (
	"encoding/json"
	"fmt"
	"math"
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

const (
	DecisionImpactContext = "context"
	DecisionImpactReview  = "review"
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
	// DecisionImpact is "context" for visible supporting observations and
	// "review" for findings that independently require a trust decision.
	// Explicit --fail-on policy remains authoritative for both.
	DecisionImpact string `json:"decision_impact,omitempty"`
	Remediation    string `json:"remediation,omitempty"`
	Analyzer       string `json:"analyzer"`
	InCodeBlock    bool   `json:"in_code_block,omitempty"`
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
	// AlsoMatched lists the findings that full deduplication merged into
	// this one because they were reported on the same file and line, in a
	// deterministic order (severity, highest first, then rule ID). It names
	// their rules only and never carries their matched text. Same-rule
	// duplicates are not listed; ScanResult.Suppressed counts every merge.
	AlsoMatched []MergedFinding `json:"also_matched,omitempty"`
	// BaselineState is set when a baseline was applied to the result:
	// "new", "baselined" or "non_baselineable".
	BaselineState string `json:"baseline_state,omitempty"`

	// Source ranges are scan-local redaction metadata, never serialized. A
	// joined match can contain evidence from more than its displayed Line.
	evidenceRanges []redactionRange
}

// MergedFinding identifies a finding that deduplication merged into the
// reported finding on the same file and line.
type MergedFinding struct {
	RuleID   string   `json:"rule_id"`
	Severity Severity `json:"severity"`
	Category string   `json:"category"`
}

// MarshalJSON adds severity_label next to the numeric severity.
func (m MergedFinding) MarshalJSON() ([]byte, error) {
	type alias MergedFinding
	return json.Marshal(struct {
		alias
		SeverityLabel string `json:"severity_label"`
	}{alias(m), m.Severity.String()})
}

// MarshalJSON adds the output-only fields of the finding contract:
// severity_label (the name of the numeric severity, which stays a number)
// and fingerprint (the value baselines and SARIF partialFingerprints use,
// omitted for findings that have none because their matched text is
// redacted). Confidence and score are rounded here, at the output boundary,
// so float noise from repeated multiplication (0.9900000000000001) does not
// reach reports; the in-memory values are unchanged.
func (f Finding) MarshalJSON() ([]byte, error) {
	type alias Finding
	a := alias(f)
	a.Confidence = RoundConfidence(a.Confidence)
	a.Score = RoundScore(a.Score)
	fp := ""
	if Fingerprintable(f) {
		fp = FindingFingerprint(f)
	}
	return json.Marshal(struct {
		alias
		SeverityLabel string `json:"severity_label"`
		Fingerprint   string `json:"fingerprint,omitempty"`
	}{a, f.Severity.String(), fp})
}

// RoundConfidence rounds a 0-1 confidence to 4 decimal places for output.
func RoundConfidence(v float64) float64 { return roundTo(v, 1e4) }

// RoundScore rounds a 0-100 score or risk score to 2 decimal places for
// output.
func RoundScore(v float64) float64 { return roundTo(v, 1e2) }

func roundTo(v, scale float64) float64 {
	if v == 0 || math.IsNaN(v) || math.IsInf(v, 0) {
		return v
	}
	return math.Round(v*scale) / scale
}

// AddEvidenceRange records source lines contributing to MatchedText. Analyzers
// that combine discontiguous matches must record each contributing range.
func (f *Finding) AddEvidenceRange(first, last int) {
	if first > 0 && last >= first {
		f.evidenceRanges = append(f.evidenceRanges, redactionRange{first, last})
	}
}

// RedactedPlaceholder is the value that replaces matched text and matching
// context lines for findings whose raw match would leak a secret. Kept as a
// stable string so JSON/SARIF consumers can grep for it consistently.
const RedactedPlaceholder = "[REDACTED]"

// RedactSensitiveFindings scrubs matched text and context lines for findings
// that are known to carry a real secret value: either the rule / analyzer set
// Sensitive == true, or the legacy category-based contract
// (Category == "credential-leak") still applies. URL userinfo is also scrubbed
// in every finding's matched text, description and source context.
//
// Context redaction differs by source. Sensitive findings treat their entire
// Context window as secret-bearing because either (a) the analyzer's
// MatchedText is a multi-line section / file blob (NLP, toxicflow) or
// (b) a pattern matcher rule with match_mode: all can land its secondary
// pattern hit on a non-IsMatch context line (EXFIL_013's `read .env` hits
// line 1, its `transmit to endpoint` hits line 2, and line 2 is then a
// non-IsMatch context line carrying the secret). The legacy credential-leak
// category only scrubs the IsMatch line, preserving the existing
// surrounding-line view that pre-Sensitive consumers rely on.
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
		// URL credentials can occur in non-credential findings and neighboring
		// source context even when the originating finding was filtered out.
		findings[i].MatchedText = SanitizeURLUserinfo(findings[i].MatchedText, RedactedPlaceholder+"@")
		findings[i].Description = SanitizeURLUserinfo(findings[i].Description, RedactedPlaceholder+"@")
		for j := range findings[i].Context {
			findings[i].Context[j].Content = SanitizeURLUserinfo(findings[i].Context[j].Content, RedactedPlaceholder+"@")
		}
		isSensitive := findings[i].Sensitive
		isLegacyCred := findings[i].Category == "credential-leak"
		if !isSensitive && !isLegacyCred {
			continue
		}
		findings[i].MatchedText = RedactedPlaceholder
		if isSensitive && findings[i].Line > 0 {
			// Analyzer findings are allowed to omit Context. Their anchor
			// line still carries the raw MatchedText and can appear inside a
			// neighboring finding's context window, so it must participate
			// in the cross-finding pass independently of Context.
			sensitiveLines[fileLine{findings[i].FilePath, findings[i].Line}] = true
		}
		for j := range findings[i].Context {
			cl := &findings[i].Context[j]
			if isSensitive {
				// Sensitive findings can carry the secret on a
				// non-IsMatch context line (multi-line analyzer
				// section, or a match_mode: all rule whose
				// secondary pattern hit lands on a context line).
				// Scrub the whole window AND mark every line for
				// cross-finding redaction.
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
	// ProfileStrict enforces all rules (default for standalone scanning): a
	// finding from a profile-enforced rule or any HIGH or CRITICAL finding
	// blocks, any other finding flags.
	ProfileStrict ScanProfile = iota
	// ProfileContentAware blocks only on findings from the caller's
	// profile-enforced rules (whatever their severity); other HIGH or
	// CRITICAL findings flag, and LOW, MEDIUM and INFO findings alone are
	// clean. Use for content/file-editing tools.
	ProfileContentAware
	// ProfileMinimal never blocks: findings from profile-enforced rules and
	// HIGH or CRITICAL findings flag; LOW, MEDIUM and INFO findings alone
	// are clean. Use for trusted internal agents.
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

// BaselineSummary describes how a scan baseline partitioned the findings,
// so terminal/JSON consumers understand why the gate passed even when
// findings are present. Set only when a baseline was applied (3A: output
// still carries every finding; the baseline affects the gate only).
type BaselineSummary struct {
	// Applied is always true when this struct is present.
	Applied bool `json:"applied"`
	// Path is the baseline file the run was diffed against.
	Path string `json:"path,omitempty"`
	// Total is the number of findings before baseline partitioning.
	Total int `json:"total"`
	// New is the number of baselineable findings NOT present in the
	// baseline. It excludes non-baselineable findings.
	New int `json:"new"`
	// Baselined is the number of findings suppressed from the gate
	// because their fingerprint was already in the baseline.
	Baselined int `json:"baselined"`
	// NonBaselineable is the number of findings that can never be
	// baselined (Sensitive / credential-leak) and are always reported.
	NonBaselineable int `json:"non_baselineable"`
	// GateCount is the number of findings that still count toward the CI
	// threshold: New + NonBaselineable. Provided so dashboards do not
	// have to add the two themselves.
	GateCount int `json:"gate_count"`
}

// ScanResult holds the complete results of a scan.
type ScanResult struct {
	Findings     []Finding        `json:"findings"`
	FilesScanned int              `json:"files_scanned"`
	RulesLoaded  int              `json:"rules_loaded"`
	Verdict      Verdict          `json:"verdict"`
	RiskScore    float64          `json:"risk_score"`
	ToolName     string           `json:"tool_name,omitempty"`
	Baseline     *BaselineSummary `json:"baseline,omitempty"`
	Duration     time.Duration    `json:"-"`
	Target       string           `json:"-"`
	// Coverage states what the scan evaluated. The CLI sets it so an
	// empty result is distinguishable from a clean one; it is omitted
	// when nil, which keeps existing library results unchanged.
	Coverage *ScanCoverage `json:"coverage,omitempty"`
	// Suppressed counts what the scan evaluated but did not report as a
	// separate finding, so a short report is distinguishable from one where
	// filters removed findings. Set by the scanner.
	Suppressed *SuppressionSummary `json:"suppressed,omitempty"`
	// TargetPolicy records target-owned policy that shaped this result.
	// It is empty unless target policy was enabled, and not serialized.
	TargetPolicy TargetPolicyUse `json:"-"`
}

// SuppressionSummary counts findings that were matched but not reported on
// their own, by the step that removed them, plus the files that project or
// caller policy excluded from the scan. The finding counts are disjoint:
// each removed finding is counted once, by the first step that removed it.
type SuppressionSummary struct {
	// Deduplicated counts findings merged into another finding reported
	// on the same file and line (see Finding.AlsoMatched).
	Deduplicated int `json:"deduplicated"`
	// BelowMinSeverity counts findings under the minimum severity filter.
	BelowMinSeverity int `json:"below_min_severity"`
	// DisabledRules counts analyzer findings removed because their rule is
	// disabled. Disabled pattern rules do not run, so they are not counted.
	DisabledRules int `json:"disabled_rules"`
	// ToolExemptions counts findings removed by built-in tool exemptions
	// or tool-scoped rule overrides.
	ToolExemptions int `json:"tool_exemptions"`
	// InlineDirectives counts findings removed by aguara-ignore directives
	// in the scanned files (applied only when project policy is trusted).
	InlineDirectives int `json:"inline_directives"`
	// ExcludedFiles counts files, not findings: entries excluded from the
	// walk by .aguaraignore or the caller's ignore patterns.
	ExcludedFiles int `json:"excluded_files"`
}

// Findings returns the number of findings the summary counts, excluding
// ExcludedFiles, which counts files.
func (s *SuppressionSummary) Findings() int {
	if s == nil {
		return 0
	}
	return s.Deduplicated + s.BelowMinSeverity + s.DisabledRules + s.ToolExemptions + s.InlineDirectives
}

// Add accumulates other into s, for callers that merge several results.
func (s *SuppressionSummary) Add(other *SuppressionSummary) {
	if s == nil || other == nil {
		return
	}
	s.Deduplicated += other.Deduplicated
	s.BelowMinSeverity += other.BelowMinSeverity
	s.DisabledRules += other.DisabledRules
	s.ToolExemptions += other.ToolExemptions
	s.InlineDirectives += other.InlineDirectives
	s.ExcludedFiles += other.ExcludedFiles
}

// TargetPolicyUse records which exclusion and suppression policy changed
// this result, so a caller can tell the user that a project's own files
// changed what was reported. A source that changed nothing is not listed.
type TargetPolicyUse struct {
	// IgnoreFile is the target's .aguaraignore when it excluded at least
	// one entry.
	IgnoreFile string
	// IgnorePatternExclusions counts entries excluded by the caller's
	// ignore patterns (the CLI passes a trusted .aguara.yml's `ignore`).
	IgnorePatternExclusions int
	// InlineSuppressed lists files whose aguara-ignore directives
	// removed at least one finding, sorted.
	InlineSuppressed []string
}

// Scan coverage scopes: which files a scan was asked to evaluate.
const (
	ScanScopePath    = "path"    // every eligible file under the target
	ScanScopeChanged = "changed" // only git-changed files under the target
	ScanScopeAuto    = "auto"    // auto-discovered MCP client configurations
)

// ScanCoverage states what a content scan evaluated.
type ScanCoverage struct {
	FilesScanned int    `json:"files_scanned"`
	Scope        string `json:"scope"`
}

// MarshalJSON implements custom JSON marshaling so Duration serializes
// as milliseconds, and normalizes the empty-results shape so consumers
// always see `"findings": []` instead of `"findings": null` on clean
// scans. The normalization covers every ScanResult producer (the
// Scanner, the CLI's aggregate runAutoScan, library callers that
// construct results directly) without each one needing to remember
// the contract. It also adds verdict_label next to the numeric verdict
// and rounds risk_score to 2 decimal places.
func (r ScanResult) MarshalJSON() ([]byte, error) {
	if r.Findings == nil {
		r.Findings = []Finding{}
	}
	r.RiskScore = RoundScore(r.RiskScore)
	type Alias ScanResult
	return json.Marshal(struct {
		Alias
		VerdictLabel string `json:"verdict_label"`
		DurationMS   int64  `json:"duration_ms"`
	}{
		Alias:        Alias(r),
		VerdictLabel: r.Verdict.String(),
		DurationMS:   r.Duration.Milliseconds(),
	})
}

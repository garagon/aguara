// Package meta provides post-processing of scan findings: deduplication,
// risk scoring, and cross-finding correlation.
package meta

import (
	"fmt"

	"github.com/garagon/aguara/internal/types"
)

// Deduplicate removes duplicate findings using DeduplicateFull mode (default).
func Deduplicate(findings []types.Finding) []types.Finding {
	return DeduplicateWithMode(findings, types.DeduplicateFull)
}

// DeduplicateWithMode removes duplicate findings according to the specified mode.
//
// Pass 1 (always): By (FilePath, RuleID, Line) — collapses same-rule duplicates on the same line.
// Pass 2 (DeduplicateFull only): By (FilePath, Line) — collapses cross-rule duplicates,
// keeping the highest severity (then highest confidence) instance.
//
// Sensitive carries forward: if any finding in a dedup group is Sensitive
// (or credential-leak category, the legacy redaction-gating signal), the
// survivor inherits Sensitive=true. Without this, a non-sensitive
// PROMPT_INJECTION finding that out-severities a co-located MCP_007 / CRED_*
// finding would win the dedup and leave the secret-bearing context line
// unscrubbed in JSON / SARIF output.
func DeduplicateWithMode(findings []types.Finding, mode types.DeduplicateMode) []types.Finding {
	// Pass 1: same-rule dedup
	byRule := make(map[string]types.Finding)
	for _, f := range findings {
		k := fmt.Sprintf("%s:%s:%d", f.FilePath, f.RuleID, f.Line)
		if existing, ok := byRule[k]; ok {
			carry := mergeSensitive(existing, f)
			if f.Severity > existing.Severity {
				f.Sensitive = carry
				byRule[k] = f
			} else {
				existing.Sensitive = carry
				byRule[k] = existing
			}
		} else {
			byRule[k] = f
		}
	}

	if mode == types.DeduplicateSameRuleOnly {
		result := make([]types.Finding, 0, len(byRule))
		for _, f := range byRule {
			result = append(result, f)
		}
		return result
	}

	// Pass 2: cross-rule dedup by (FilePath, Line)
	byLine := make(map[string]types.Finding)
	for _, f := range byRule {
		k := fmt.Sprintf("%s:%d", f.FilePath, f.Line)
		if existing, ok := byLine[k]; ok {
			carry := mergeSensitive(existing, f)
			if f.Severity > existing.Severity ||
				(f.Severity == existing.Severity && f.Confidence > existing.Confidence) ||
				(f.Severity == existing.Severity && f.Confidence == existing.Confidence && f.RuleID < existing.RuleID) {
				f.Sensitive = carry
				byLine[k] = f
			} else {
				existing.Sensitive = carry
				byLine[k] = existing
			}
		} else {
			byLine[k] = f
		}
	}

	result := make([]types.Finding, 0, len(byLine))
	for _, f := range byLine {
		result = append(result, f)
	}
	return result
}

// mergeSensitive returns true if either finding in a dedup group carries the
// redaction obligation: an explicit Sensitive flag or the legacy
// credential-leak category. The survivor of the dedup inherits this so the
// downstream redaction boundary still scrubs the matched line and context.
func mergeSensitive(a, b types.Finding) bool {
	return a.Sensitive || b.Sensitive ||
		a.Category == "credential-leak" || b.Category == "credential-leak"
}

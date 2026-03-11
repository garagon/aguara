// Package meta provides post-processing of scan findings: deduplication,
// risk scoring, and cross-finding correlation.
package meta

import (
	"fmt"

	"github.com/garagon/aguara/internal/types"
)

// Deduplicate removes duplicate findings in two passes:
//  1. By (FilePath, RuleID, Line) — collapses same-rule duplicates on the same line.
//  2. By (FilePath, Line) — collapses cross-rule duplicates on the same line,
//     keeping the highest severity (then highest confidence) instance.
func Deduplicate(findings []types.Finding) []types.Finding {
	// Pass 1: same-rule dedup
	byRule := make(map[string]types.Finding)
	for _, f := range findings {
		k := fmt.Sprintf("%s:%s:%d", f.FilePath, f.RuleID, f.Line)
		if existing, ok := byRule[k]; ok {
			if f.Severity > existing.Severity {
				byRule[k] = f
			}
		} else {
			byRule[k] = f
		}
	}

	// Pass 2: cross-rule dedup by (FilePath, Line)
	byLine := make(map[string]types.Finding)
	for _, f := range byRule {
		k := fmt.Sprintf("%s:%d", f.FilePath, f.Line)
		if existing, ok := byLine[k]; ok {
			if f.Severity > existing.Severity ||
				(f.Severity == existing.Severity && f.Confidence > existing.Confidence) ||
				(f.Severity == existing.Severity && f.Confidence == existing.Confidence && f.RuleID < existing.RuleID) {
				byLine[k] = f
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

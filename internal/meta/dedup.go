// Package meta provides post-processing of scan findings: deduplication,
// risk scoring, and cross-finding correlation.
package meta

import (
	"fmt"
	"sort"

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
//
// DecisionImpact also carries forward conservatively: if any finding in a
// collapsed group independently requires review, the visible survivor remains
// review-impact even when a context rule wins the severity/confidence tie.
//
// The survivor of a cross-rule merge (pass 2) lists the findings it absorbed
// in AlsoMatched: rule ID, severity and category only, never matched text,
// sorted by severity (highest first), then rule ID and category. Which
// finding survives and every other field of the survivor are unchanged.
// The number of findings removed is len(findings) minus the length of the
// result.
func DeduplicateWithMode(findings []types.Finding, mode types.DeduplicateMode) []types.Finding {
	// Pass 1: same-rule dedup
	byRule := make(map[string]types.Finding)
	for _, f := range findings {
		k := fmt.Sprintf("%s:%s:%d", f.FilePath, f.RuleID, f.Line)
		if existing, ok := byRule[k]; ok {
			carrySensitive := mergeSensitive(existing, f)
			carryImpact := mergeDecisionImpact(existing, f)
			if f.Severity > existing.Severity {
				f.Sensitive = carrySensitive
				f.DecisionImpact = carryImpact
				f.AlsoMatched = mergeAbsorbed(f, existing)
				byRule[k] = f
			} else {
				existing.Sensitive = carrySensitive
				existing.DecisionImpact = carryImpact
				existing.AlsoMatched = mergeAbsorbed(existing, f)
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
			carrySensitive := mergeSensitive(existing, f)
			carryImpact := mergeDecisionImpact(existing, f)
			if f.Severity > existing.Severity ||
				(f.Severity == existing.Severity && f.Confidence > existing.Confidence) ||
				(f.Severity == existing.Severity && f.Confidence == existing.Confidence && f.RuleID < existing.RuleID) {
				f.Sensitive = carrySensitive
				f.DecisionImpact = carryImpact
				f.AlsoMatched = mergeAbsorbed(f, existing)
				byLine[k] = f
			} else {
				existing.Sensitive = carrySensitive
				existing.DecisionImpact = carryImpact
				existing.AlsoMatched = mergeAbsorbed(existing, f)
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

// mergeAbsorbed returns the AlsoMatched list of survivor after it absorbs
// loser: both existing lists plus loser itself, without entries for the
// survivor's own rule, deduplicated and in a deterministic order.
func mergeAbsorbed(survivor, loser types.Finding) []types.MergedFinding {
	all := make([]types.MergedFinding, 0, len(survivor.AlsoMatched)+len(loser.AlsoMatched)+1)
	all = append(all, survivor.AlsoMatched...)
	all = append(all, loser.AlsoMatched...)
	all = append(all, types.MergedFinding{RuleID: loser.RuleID, Severity: loser.Severity, Category: loser.Category})
	sort.Slice(all, func(i, j int) bool {
		if all[i].Severity != all[j].Severity {
			return all[i].Severity > all[j].Severity
		}
		if all[i].RuleID != all[j].RuleID {
			return all[i].RuleID < all[j].RuleID
		}
		return all[i].Category < all[j].Category
	})
	out := all[:0]
	for _, m := range all {
		if m.RuleID == survivor.RuleID {
			continue
		}
		if n := len(out); n > 0 && out[n-1] == m {
			continue
		}
		out = append(out, m)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// mergeSensitive returns true if either finding in a dedup group carries the
// redaction obligation: an explicit Sensitive flag or the legacy
// credential-leak category. The survivor of the dedup inherits this so the
// downstream redaction boundary still scrubs the matched line and context.
func mergeSensitive(a, b types.Finding) bool {
	return a.Sensitive || b.Sensitive ||
		a.Category == "credential-leak" || b.Category == "credential-leak"
}

func mergeDecisionImpact(a, b types.Finding) string {
	if a.DecisionImpact == "" && b.DecisionImpact == "" {
		return ""
	}
	if a.DecisionImpact == types.DecisionImpactContext &&
		b.DecisionImpact == types.DecisionImpactContext {
		return types.DecisionImpactContext
	}
	return types.DecisionImpactReview
}

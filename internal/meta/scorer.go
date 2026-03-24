package meta

import (
	"sort"

	"github.com/garagon/aguara/internal/types"
)

// Category multipliers for risk scoring.
var categoryMultiplier = map[string]float64{
	"prompt-injection":    1.5,
	"exfiltration":        1.4,
	"credential-leak":     1.3,
	"code-execution":      1.3,
	"command-execution":   1.3,
	"data-exposure":       1.1,
	"mcp-attack":          1.5,
	"ssrf-cloud":          1.4,
	"supply-chain":        1.4,
	"external-download":   1.3,
	"indirect-injection":  1.4,
	"third-party-content": 1.2,
	"unicode-attack":      1.2,
	"mcp-config":          1.3,
	"rug-pull":            1.5,
	"toxic-flow":          1.4,
}

// severityBase maps severity to base score points.
var severityBase = map[types.Severity]float64{
	types.SeverityCritical: 40,
	types.SeverityHigh:     25,
	types.SeverityMedium:   15,
	types.SeverityLow:      8,
	types.SeverityInfo:     3,
}

// ScoreFindings assigns a numeric risk score (0-100) to each finding.
func ScoreFindings(findings []types.Finding) []types.Finding {
	for i := range findings {
		base := severityBase[findings[i].Severity]
		mult := categoryMultiplier[findings[i].Category]
		if mult == 0 {
			mult = 1.0
		}
		score := base * mult
		if score > 100 {
			score = 100
		}
		findings[i].Score = score
	}
	return findings
}

// ComputeRiskScore computes an aggregate risk score (0-100) from all findings.
// Uses diminishing returns: the highest-scoring finding contributes 100%,
// the second 50%, the third 25%, etc.
func ComputeRiskScore(findings []types.Finding) float64 {
	if len(findings) == 0 {
		return 0
	}

	sorted := make([]types.Finding, len(findings))
	copy(sorted, findings)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Score > sorted[j].Score
	})

	total := 0.0
	for i, f := range sorted {
		weight := 1.0 / float64(int(1) << i)
		total += f.Score * weight
	}
	if total > 100 {
		total = 100
	}
	return total
}

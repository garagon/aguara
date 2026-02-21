package meta

import "github.com/garagon/aguara/internal/types"

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

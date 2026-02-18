package meta

import (
	"sort"

	"github.com/garagon/aguara/internal/types"
)

// CorrelationGroup groups related findings by file and line proximity.
type CorrelationGroup struct {
	FilePath string
	Findings []types.Finding
	MaxScore float64
}

// Correlate groups findings that share the same file and have overlapping line ranges.
func Correlate(findings []types.Finding) []CorrelationGroup {
	// Group by file first
	byFile := make(map[string][]types.Finding)
	for _, f := range findings {
		byFile[f.FilePath] = append(byFile[f.FilePath], f)
	}

	var groups []CorrelationGroup
	for filePath, fileFindings := range byFile {
		// Sort by line
		sort.Slice(fileFindings, func(i, j int) bool {
			return fileFindings[i].Line < fileFindings[j].Line
		})

		// Merge findings within 5 lines of each other
		var current []types.Finding
		for _, f := range fileFindings {
			if len(current) == 0 {
				current = append(current, f)
				continue
			}
			lastLine := current[len(current)-1].Line
			if f.Line-lastLine <= 5 {
				current = append(current, f)
			} else {
				groups = append(groups, makeGroup(filePath, current))
				current = []types.Finding{f}
			}
		}
		if len(current) > 0 {
			groups = append(groups, makeGroup(filePath, current))
		}
	}

	// Apply correlation bonus: groups with multiple findings get a score boost
	for i := range groups {
		if len(groups[i].Findings) > 1 {
			bonus := float64(len(groups[i].Findings)-1) * 5
			for j := range groups[i].Findings {
				groups[i].Findings[j].Score += bonus
				if groups[i].Findings[j].Score > 100 {
					groups[i].Findings[j].Score = 100
				}
			}
		}
	}

	return groups
}

func makeGroup(filePath string, findings []types.Finding) CorrelationGroup {
	var maxScore float64
	for _, f := range findings {
		if f.Score > maxScore {
			maxScore = f.Score
		}
	}
	return CorrelationGroup{
		FilePath: filePath,
		Findings: findings,
		MaxScore: maxScore,
	}
}

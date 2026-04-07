package meta

import (
	"sort"

	"github.com/garagon/aguara/internal/types"
)

// AdjustConfidence applies post-processing adjustments to finding confidence
// values based on contextual signals like code blocks and correlation.
func AdjustConfidence(findings []types.Finding) []types.Finding {
	// Pass 1: downgrade confidence for findings inside code blocks
	for i := range findings {
		if findings[i].InCodeBlock && findings[i].Confidence > 0 {
			findings[i].Confidence *= 0.6
		}
	}

	// Pass 2: boost confidence for correlated findings (same file, within 5 lines).
	// O(n log n) via sorted line numbers instead of O(n^2) nested loop.
	byFile := make(map[string][]int)
	for i := range findings {
		byFile[findings[i].FilePath] = append(byFile[findings[i].FilePath], i)
	}

	for _, indices := range byFile {
		if len(indices) < 2 {
			continue
		}
		// Sort indices by line number
		sort.Slice(indices, func(a, b int) bool {
			return findings[indices[a]].Line < findings[indices[b]].Line
		})
		// Mark findings that have a neighbor within 5 lines
		correlated := make(map[int]bool)
		for k := 1; k < len(indices); k++ {
			if findings[indices[k]].Line-findings[indices[k-1]].Line <= 5 {
				correlated[indices[k]] = true
				correlated[indices[k-1]] = true
			}
		}
		for idx := range correlated {
			if findings[idx].Confidence > 0 {
				findings[idx].Confidence *= 1.1
				if findings[idx].Confidence > 1.0 {
					findings[idx].Confidence = 1.0
				}
			}
		}
	}

	// Pass 3: clamp negative confidence values to zero
	for i := range findings {
		if findings[i].Confidence < 0 {
			findings[i].Confidence = 0
		}
	}

	return findings
}

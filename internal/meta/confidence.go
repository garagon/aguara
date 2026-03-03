package meta

import "github.com/garagon/aguara/internal/types"

// AdjustConfidence applies post-processing adjustments to finding confidence
// values based on contextual signals like code blocks and correlation.
func AdjustConfidence(findings []types.Finding) []types.Finding {
	// Pass 1: downgrade confidence for findings inside code blocks
	for i := range findings {
		if findings[i].InCodeBlock && findings[i].Confidence > 0 {
			findings[i].Confidence *= 0.6
		}
	}

	// Pass 2: boost confidence for correlated findings (same file, within 5 lines)
	byFile := make(map[string][]int)
	for i := range findings {
		byFile[findings[i].FilePath] = append(byFile[findings[i].FilePath], i)
	}

	for _, indices := range byFile {
		for _, i := range indices {
			correlated := false
			for _, j := range indices {
				if i == j {
					continue
				}
				diff := findings[i].Line - findings[j].Line
				if diff < 0 {
					diff = -diff
				}
				if diff <= 5 {
					correlated = true
					break
				}
			}
			if correlated && findings[i].Confidence > 0 {
				findings[i].Confidence *= 1.1
				if findings[i].Confidence > 1.0 {
					findings[i].Confidence = 1.0
				}
			}
		}
	}

	return findings
}

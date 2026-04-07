package meta

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/garagon/aguara/internal/types"
)

// docSectionHeadings are markdown headings that indicate documentation context.
// Findings near these headings are more likely false positives.
var docSectionHeadings = []string{
	"## installation",
	"## install",
	"## setup",
	"## getting started",
	"## usage",
	"## quick start",
	"## quickstart",
	"## prerequisites",
	"## requirements",
	"## dependencies",
	"## building",
	"## build",
	"## configuration",
	"## config",
	"## development",
	"## contributing",
	"## changelog",
	"## license",
	"## faq",
	"## troubleshooting",
	"# installation",
	"# install",
	"# setup",
	"# getting started",
	"# usage",
	"# quick start",
}

// AdjustConfidence applies post-processing adjustments to finding confidence
// values based on contextual signals like code blocks, documentation sections,
// file type, and correlation.
func AdjustConfidence(findings []types.Finding) []types.Finding {
	// Pass 1: downgrade confidence for findings inside code blocks
	for i := range findings {
		if findings[i].InCodeBlock && findings[i].Confidence > 0 {
			findings[i].Confidence *= 0.6
		}
	}

	// Pass 1b: downgrade confidence for findings in documentation sections.
	// If the context lines contain a documentation heading (like "## Installation"),
	// the finding is likely a usage example, not a real vulnerability.
	for i := range findings {
		if findings[i].Confidence > 0 && inDocSection(findings[i].Context) {
			findings[i].Confidence *= 0.7
		}
	}

	// Pass 1c: apply file-type confidence multiplier.
	// Documentation files (.md, .txt) get a slight penalty since patterns
	// matching in prose are more likely to be examples than real threats.
	for i := range findings {
		if findings[i].Confidence > 0 {
			mult := fileTypeMultiplier(findings[i].FilePath)
			if mult != 1.0 {
				findings[i].Confidence *= mult
			}
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

// inDocSection checks if any context line is a documentation section heading.
func inDocSection(ctx []types.ContextLine) bool {
	for _, cl := range ctx {
		lower := strings.ToLower(strings.TrimSpace(cl.Content))
		for _, heading := range docSectionHeadings {
			if lower == heading || strings.HasPrefix(lower, heading+" ") {
				return true
			}
		}
	}
	return false
}

// fileTypeMultiplier returns a confidence multiplier based on file extension.
// Documentation formats get a slight penalty (0.9) while executable/config
// files get no adjustment (1.0).
func fileTypeMultiplier(filePath string) float64 {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".md", ".markdown", ".txt", ".rst":
		return 0.9
	default:
		return 1.0
	}
}

// Package toxicflow cross-file detection: detects dangerous capability
// combinations across files within the same directory.
package toxicflow

import (
	"fmt"
	"path/filepath"
	"sync"

	"github.com/garagon/aguara/internal/types"
)

// capFileMatch stores where a capability was detected in a file.
type capFileMatch struct {
	filePath string
	text     string
	line     int
}

// maxFilesPerDir is the threshold above which a directory is considered a
// flat registry (independent skills) rather than a single MCP server.
// Cross-file analysis is skipped for such directories to avoid false positives.
const maxFilesPerDir = 50

// CrossFileAnalyzer detects toxic capability combinations across files
// in the same directory. Thread-safe for concurrent per-file accumulation.
type CrossFileAnalyzer struct {
	mu       sync.Mutex
	byDir    map[string]map[capability][]capFileMatch // dir -> capability -> file matches
	dirFiles map[string]int                           // dir -> file count
}

// NewCrossFileAnalyzer creates a new cross-file analyzer.
func NewCrossFileAnalyzer() *CrossFileAnalyzer {
	return &CrossFileAnalyzer{
		byDir:    make(map[string]map[capability][]capFileMatch),
		dirFiles: make(map[string]int),
	}
}

// crossFileToxicPairs define cross-file toxic combinations.
// sensitive mirrors toxicPairs: true when the "a" side reads private data,
// so the matched text quoting both files can include secret values.
var crossFileToxicPairs = []toxicPair{
	{
		a:           readsPrivateData,
		b:           writesPublicOutput,
		ruleID:      "TOXIC_CROSS_001",
		name:        "Cross-file: private data read with public output",
		description: "One file reads private data while another in the same directory writes to public channels. This combination enables data exfiltration across tool boundaries.",
		sensitive:   true,
	},
	{
		a:           readsPrivateData,
		b:           executesCode,
		ruleID:      "TOXIC_CROSS_002",
		name:        "Cross-file: private data read with code execution",
		description: "One file reads private data while another in the same directory executes arbitrary code. This combination enables credential theft across tool boundaries.",
		sensitive:   true,
	},
	{
		a:           destructive,
		b:           executesCode,
		ruleID:      "TOXIC_CROSS_003",
		name:        "Cross-file: destructive actions with code execution",
		description: "One file has destructive capabilities while another in the same directory executes arbitrary code. This combination enables ransomware-like attacks across tool boundaries.",
	},
}

// Accumulate classifies capabilities for a single file and stores results.
// Called by the scanner for each file during the scan phase.
func (c *CrossFileAnalyzer) Accumulate(relPath string, content string) {
	dir := filepath.Dir(relPath)

	c.mu.Lock()
	c.dirFiles[dir]++
	c.mu.Unlock()

	for _, cp := range classifiers {
		for _, pat := range cp.patterns {
			loc := pat.FindStringIndex(content)
			if loc == nil {
				continue
			}
			line := 1
			for i := 0; i < loc[0] && i < len(content); i++ {
				if content[i] == '\n' {
					line++
				}
			}
			c.mu.Lock()
			if c.byDir[dir] == nil {
				c.byDir[dir] = make(map[capability][]capFileMatch)
			}
			c.byDir[dir][cp.cap] = append(c.byDir[dir][cp.cap], capFileMatch{
				filePath: relPath,
				text:     content[loc[0]:loc[1]],
				line:     line,
			})
			c.mu.Unlock()
			break // one match per capability per file
		}
	}
}

// Finalize checks for toxic pairs across files within each directory.
// Called after all files have been processed.
func (c *CrossFileAnalyzer) Finalize() []types.Finding {
	c.mu.Lock()
	defer c.mu.Unlock()

	var findings []types.Finding

	for dir, caps := range c.byDir {
		// Skip directories with many files - likely a flat registry of
		// independent skills rather than a single MCP server.
		if c.dirFiles[dir] > maxFilesPerDir {
			continue
		}
		for _, tp := range crossFileToxicPairs {
			matchesA := caps[tp.a]
			matchesB := caps[tp.b]
			if len(matchesA) == 0 || len(matchesB) == 0 {
				continue
			}

			// Check if A and B come from different files
			for _, a := range matchesA {
				for _, b := range matchesB {
					if a.filePath == b.filePath {
						continue // same file = already caught by single-file analyzer
					}

					// Use the sink file (more dangerous capability) as the finding location
					matchedText := fmt.Sprintf("[%s] %s (%s) + [%s] %s (%s)",
						tp.a, a.text, a.filePath,
						tp.b, b.text, b.filePath)

					findings = append(findings, types.Finding{
						RuleID:      tp.ruleID,
						RuleName:    tp.name,
						Severity:    types.SeverityHigh,
						Category:    "toxic-flow",
						Description: fmt.Sprintf("%s File %s has [%s], file %s has [%s].", tp.description, a.filePath, tp.a, b.filePath, tp.b),
						FilePath:    b.filePath, // sink file
						Line:        b.line,
						MatchedText: matchedText,
						Analyzer:    "toxicflow-crossfile",
						Sensitive:   tp.sensitive,
						Confidence:  0.85,
					})

					// Only report one pair per toxic combination per directory
					goto nextPair
				}
			}
		nextPair:
		}
	}

	return findings
}

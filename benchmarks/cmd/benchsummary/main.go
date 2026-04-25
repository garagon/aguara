// Command benchsummary collapses an Aguara JSON scan result into a stable
// text report for benchmark diffs across PRs.
//
// The command does NOT modify scan output, rules, or scanner behaviour. It
// only reads the JSON, counts, and prints. Output format is deliberately
// boring -- key: value pairs and indented sections -- so a future PR can
// `diff` two summaries and surface meaningful regressions:
//
//   - aumento brusco de findings totales
//   - aumento de HIGH/CRITICAL dentro de code blocks (likely FP source)
//   - nuevas reglas dominando el corpus
//   - cambios inesperados en cantidad de archivos escaneados
//
// "Low confidence HIGH/CRITICAL" is defined here as `severity >= HIGH AND
// in_code_block == true`, per the benchmark spec. Code-block matches are
// the most common false-positive class because rule examples, test
// fixtures, and documented attack patterns all live in fenced code blocks.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

type scanResult struct {
	Findings     []finding `json:"findings"`
	FilesScanned int       `json:"files_scanned"`
	RulesLoaded  int       `json:"rules_loaded"`
	Verdict      int       `json:"verdict"`
	RiskScore    float64   `json:"risk_score"`
	DurationMS   int64     `json:"duration_ms"`
}

type finding struct {
	RuleID      string `json:"rule_id"`
	Severity    int    `json:"severity"`
	Category    string `json:"category"`
	FilePath    string `json:"file_path"`
	InCodeBlock bool   `json:"in_code_block"`
}

type kv struct {
	Key   string
	Count int
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: benchsummary <scan-result.json>\n")
		os.Exit(2)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "read scan result: %v\n", err)
		os.Exit(1)
	}

	var result scanResult
	if err := json.Unmarshal(data, &result); err != nil {
		fmt.Fprintf(os.Stderr, "parse scan result: %v\n", err)
		os.Exit(1)
	}

	sevCounts := map[int]int{}
	catCounts := map[string]int{}
	ruleCounts := map[string]int{}
	highRuleCounts := map[string]int{}
	codeBlockRuleCounts := map[string]int{}
	lowConfidenceHighRuleCounts := map[string]int{}
	fileCounts := map[string]int{}
	codeBlockFindings := 0
	lowConfidenceHighs := 0

	for _, f := range result.Findings {
		sevCounts[f.Severity]++
		catCounts[f.Category]++
		ruleCounts[f.RuleID]++
		fileCounts[f.FilePath]++
		if f.Severity >= 3 {
			highRuleCounts[f.RuleID]++
			// Spec definition of "low confidence HIGH/CRITICAL": a HIGH or
			// CRITICAL finding sitting inside a markdown code block. Code
			// blocks are where rule examples, test fixtures, and docs of
			// attack patterns live, so this overlaps strongly with the FP
			// surface for severity escalation.
			if f.InCodeBlock {
				lowConfidenceHighs++
				lowConfidenceHighRuleCounts[f.RuleID]++
			}
		}
		if f.InCodeBlock {
			codeBlockFindings++
			codeBlockRuleCounts[f.RuleID]++
		}
	}

	// Header block: stable key:value lines so a future PR can grep deltas.
	fmt.Printf("files_scanned: %d\n", result.FilesScanned)
	fmt.Printf("rules_loaded: %d\n", result.RulesLoaded)
	fmt.Printf("duration_ms: %d\n", result.DurationMS)
	fmt.Printf("findings: %d\n", len(result.Findings))
	fmt.Printf("risk_score: %s\n", formatRisk(result.RiskScore))
	fmt.Printf("verdict: %s\n", verdictName(result.Verdict))
	fmt.Printf("findings_in_code: %d\n", codeBlockFindings)
	fmt.Printf("high_low_confidence: %d\n", lowConfidenceHighs)
	fmt.Println()

	printSeverity(sevCounts)
	printSection("top_categories", catCounts, 20)
	printSection("top_rules", ruleCounts, 30)
	printSection("top_high_critical", highRuleCounts, 30)
	printSection("top_code_block_rules", codeBlockRuleCounts, 30)
	printSection("top_low_confidence_high_critical", lowConfidenceHighRuleCounts, 30)
	printSection("top_affected_files", fileCounts, 20)
}

// formatRisk prints whole-number risk scores without a trailing .0 (so
// 100.0 reads as 100) but keeps fractional precision for non-whole values.
func formatRisk(v float64) string {
	if v == float64(int64(v)) {
		return fmt.Sprintf("%d", int64(v))
	}
	return fmt.Sprintf("%.1f", v)
}

func printSeverity(counts map[int]int) {
	fmt.Println("severity:")
	// Stable ordering: highest severity first, omit zero buckets.
	for _, sev := range []int{4, 3, 2, 1, 0} {
		if counts[sev] == 0 {
			continue
		}
		fmt.Printf("  %s: %d\n", severityName(sev), counts[sev])
	}
	fmt.Println()
}

func printSection(title string, counts map[string]int, limit int) {
	if len(counts) == 0 {
		return
	}
	fmt.Printf("%s:\n", title)

	items := make([]kv, 0, len(counts))
	for k, v := range counts {
		items = append(items, kv{Key: k, Count: v})
	}
	// Sort by count desc, then key asc, so the output is deterministic
	// across runs (map iteration order would otherwise reorder ties).
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count != items[j].Count {
			return items[i].Count > items[j].Count
		}
		return items[i].Key < items[j].Key
	})
	if len(items) > limit {
		items = items[:limit]
	}
	for _, item := range items {
		fmt.Printf("  %s: %d\n", item.Key, item.Count)
	}
	fmt.Println()
}

func severityName(sev int) string {
	switch sev {
	case 4:
		return "CRITICAL"
	case 3:
		return "HIGH"
	case 2:
		return "MEDIUM"
	case 1:
		return "LOW"
	case 0:
		return "INFO"
	default:
		return "UNKNOWN"
	}
}

func verdictName(v int) string {
	// Mirrors internal/types/types.go Verdict enum (clean=0, flag=1, block=2).
	switch v {
	case 0:
		return "clean"
	case 1:
		return "flag"
	case 2:
		return "block"
	default:
		return "unknown"
	}
}

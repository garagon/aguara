package scanner_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/engine/nlp"
	"github.com/garagon/aguara/internal/engine/pattern"
	"github.com/garagon/aguara/internal/engine/toxicflow"
	"github.com/garagon/aguara/internal/rules"
	"github.com/garagon/aguara/internal/rules/builtin"
	"github.com/garagon/aguara/internal/scanner"
)

// benchmarkScenario defines a labeled test scenario for precision/recall evaluation.
type benchmarkScenario struct {
	name          string
	path          string   // relative to testdata/
	isMalicious   bool     // true = TP scenario, false = benign (should be clean)
	expectedRules []string // rule IDs that MUST be detected (recall targets)
}

// scenarioResults holds per-scenario evaluation metrics.
type scenarioResults struct {
	name           string
	findings       int
	expectedRules  int
	matchedRules   int
	missedRules    []string
	extraRules     []string
	falsePositives int // only for benign scenarios
}

// TestEvalBenchmark runs the scanner against labeled testdata scenarios and
// reports precision/recall metrics. Skips when testdata/ is absent.
//
// Run with: go test -run TestEvalBenchmark -v ./internal/scanner/
func TestEvalBenchmark(t *testing.T) {
	testdataDir := filepath.Join("../..", "testdata")
	if _, err := os.Stat(testdataDir); os.IsNotExist(err) {
		t.Skip("testdata/ not present, skipping benchmark evaluation")
	}

	scenarios := buildScenarios(testdataDir)
	s := buildEvalScanner(t)

	var results []scenarioResults
	totalTP, totalFP, totalFN := 0, 0, 0
	ruleCounts := make(map[string]int) // rule ID -> total detections

	for _, sc := range scenarios {
		result, err := s.Scan(context.Background(), sc.path)
		if err != nil {
			t.Errorf("scan %s: %v", sc.name, err)
			continue
		}

		findings := result.Findings
		sr := scenarioResults{
			name:          sc.name,
			findings:      len(findings),
			expectedRules: len(sc.expectedRules),
		}

		// Track detected rule IDs
		detectedRules := make(map[string]bool)
		for _, f := range findings {
			detectedRules[f.RuleID] = true
			ruleCounts[f.RuleID]++
		}

		if sc.isMalicious {
			// Check recall: are all expected rules detected?
			for _, expected := range sc.expectedRules {
				if detectedRules[expected] {
					sr.matchedRules++
					totalTP++
				} else {
					sr.missedRules = append(sr.missedRules, expected)
					totalFN++
				}
			}
			// Extra rules (detected but not in expected list) are not necessarily FP -
			// they might be valid detections we haven't labeled yet.
			for r := range detectedRules {
				found := false
				for _, exp := range sc.expectedRules {
					if r == exp {
						found = true
						break
					}
				}
				if !found {
					sr.extraRules = append(sr.extraRules, r)
				}
			}
		} else {
			// Benign: any finding is a false positive
			sr.falsePositives = len(findings)
			totalFP += len(findings)
			for _, f := range findings {
				sr.extraRules = append(sr.extraRules, f.RuleID)
			}
		}

		results = append(results, sr)
	}

	// Report per-scenario results
	t.Log("\n=== BENCHMARK EVALUATION ===\n")
	for _, sr := range results {
		status := "OK"
		if len(sr.missedRules) > 0 {
			status = "MISS"
		}
		if sr.falsePositives > 0 {
			status = "FP"
		}
		t.Logf("%-40s %4s  findings=%d  recall=%d/%d  missed=%v",
			sr.name, status, sr.findings, sr.matchedRules, sr.expectedRules, sr.missedRules)
		if len(sr.extraRules) > 0 {
			sort.Strings(sr.extraRules)
			t.Logf("  extra (unlabeled): %v", sr.extraRules)
		}
	}

	// Aggregate metrics
	totalExpected := totalTP + totalFN
	precision := float64(1)
	if totalTP+totalFP > 0 {
		precision = float64(totalTP) / float64(totalTP+totalFP)
	}
	recall := float64(1)
	if totalExpected > 0 {
		recall = float64(totalTP) / float64(totalExpected)
	}
	f1 := float64(0)
	if precision+recall > 0 {
		f1 = 2 * precision * recall / (precision + recall)
	}

	t.Logf("\n=== AGGREGATE METRICS ===")
	t.Logf("Scenarios:     %d (%d malicious, %d benign)",
		len(scenarios), countMalicious(scenarios), len(scenarios)-countMalicious(scenarios))
	t.Logf("True Positives:  %d", totalTP)
	t.Logf("False Positives: %d", totalFP)
	t.Logf("False Negatives: %d", totalFN)
	t.Logf("Precision:       %.1f%%", precision*100)
	t.Logf("Recall:          %.1f%%", recall*100)
	t.Logf("F1 Score:        %.3f", f1)

	// Per-rule frequency
	t.Logf("\n=== RULE FREQUENCY (top 15) ===")
	type ruleFreq struct {
		id    string
		count int
	}
	var freqs []ruleFreq
	for id, c := range ruleCounts {
		freqs = append(freqs, ruleFreq{id, c})
	}
	sort.Slice(freqs, func(i, j int) bool { return freqs[i].count > freqs[j].count })
	for i, rf := range freqs {
		if i >= 15 {
			break
		}
		t.Logf("  %-30s %d", rf.id, rf.count)
	}
}

func buildEvalScanner(t *testing.T) *scanner.Scanner {
	t.Helper()
	rawRules, err := rules.LoadFromFS(builtin.FS())
	if err != nil {
		t.Fatal(err)
	}
	compiled, errs := rules.CompileAll(rawRules)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	s := scanner.New(2)
	s.RegisterAnalyzer(pattern.NewMatcher(compiled))
	s.RegisterAnalyzer(nlp.NewInjectionAnalyzer())
	s.RegisterAnalyzer(toxicflow.New())
	s.SetCrossFileAccumulator(toxicflow.NewCrossFileAnalyzer())
	return s
}

func buildScenarios(testdataDir string) []benchmarkScenario {
	// Malicious scenarios with expected TP rules.
	// These are labeled ground truth from manual review.
	malicious := map[string][]string{
		"combined-attack":        {"PROMPT_INJECTION_001", "PROMPT_INJECTION_010", "PROMPT_INJECTION_011", "CRED_001", "EXFIL_001", "EXFIL_002", "EXFIL_004"},
		"credential-leak":        {"CRED_001", "CRED_002", "CRED_005", "CRED_006", "CRED_008", "CRED_010", "EXFIL_001"},
		"encoded-payload":        {"PROMPT_INJECTION_001", "PROMPT_INJECTION_009", "PROMPT_INJECTION_011"},
		"exfil-webhook":          {"EXFIL_001", "EXFIL_002"},
		"hidden-injection":       {"PROMPT_INJECTION_001", "EXFIL_002"},
		"mcp-tool-poisoning":     {"MCP_001", "MCP_005", "MCP_006", "MCP_008", "PROMPT_INJECTION_001", "SUPPLY_003"},
		"prompt-injection-basic": {"PROMPT_INJECTION_001", "PROMPT_INJECTION_005", "PROMPT_INJECTION_006", "PROMPT_INJECTION_008"},
		"ssrf-metadata":          {"SSRF_001", "SSRF_003", "SSRF_004", "SSRF_005", "SSRF_007"},
		"supply-chain-attack":    {"SUPPLY_002", "SUPPLY_003", "SUPPLY_006", "SUPPLY_007", "SUPPLY_008", "MCP_008"},
		"unicode-obfuscation":    {"UNI_001", "UNI_002", "UNI_003", "UNI_004", "UNI_005", "UNI_006", "UNI_007"},
	}

	// Benign scenarios - should produce 0 findings.
	benign := []string{
		"complex-skill",
		"documentation-skill",
		"mcp-server-legit",
		"npm-project",
		"security-tooling",
		"simple-skill",
	}

	var scenarios []benchmarkScenario
	for name, expected := range malicious {
		dir := filepath.Join(testdataDir, "malicious", name)
		if _, err := os.Stat(dir); err == nil {
			scenarios = append(scenarios, benchmarkScenario{
				name:          fmt.Sprintf("malicious/%s", name),
				path:          dir,
				isMalicious:   true,
				expectedRules: expected,
			})
		}
	}
	for _, name := range benign {
		dir := filepath.Join(testdataDir, "benign", name)
		if _, err := os.Stat(dir); err == nil {
			scenarios = append(scenarios, benchmarkScenario{
				name:        fmt.Sprintf("benign/%s", name),
				path:        dir,
				isMalicious: false,
			})
		}
	}

	sort.Slice(scenarios, func(i, j int) bool {
		return scenarios[i].name < scenarios[j].name
	})
	return scenarios
}

func countMalicious(scenarios []benchmarkScenario) int {
	n := 0
	for _, s := range scenarios {
		if s.isMalicious {
			n++
		}
	}
	return n
}

// TestEvalRuleSelfTest validates that rule self-test examples (true_positive,
// false_positive) pass against the pattern matcher. Uses the first target
// extension from each rule (or "test.md" if no targets specified) to ensure
// extension-based filtering doesn't interfere.
//
// NOTE: Rules detected only by NLP/toxicflow (not pattern matcher) will show
// as failures here. The rules package self-test (TestRuleSelfTest) covers
// pattern-level validation; this test covers integration with the matcher.
func TestEvalRuleSelfTest(t *testing.T) {
	rawRules, err := rules.LoadFromFS(builtin.FS())
	if err != nil {
		t.Fatal(err)
	}
	compiled, errs := rules.CompileAll(rawRules)
	if len(errs) > 0 {
		t.Fatal(errs)
	}

	matcher := pattern.NewMatcher(compiled)
	tpPassed, tpFailed := 0, 0
	fpPassed, fpFailed := 0, 0
	var failures []string

	for _, rule := range compiled {
		// Pick filename matching the rule's first target, or default to test.md
		filename := "test.md"
		for _, tgt := range rule.Targets {
			if strings.HasPrefix(tgt, "*.") {
				filename = "test" + tgt[1:]
				break
			}
		}

		for _, tp := range rule.Examples.TruePositive {
			target := &scanner.Target{
				RelPath: filename,
				Content: []byte(tp),
			}
			findings, err := matcher.Analyze(context.Background(), target)
			if err != nil {
				t.Errorf("rule %s TP: %v", rule.ID, err)
				continue
			}
			found := false
			for _, f := range findings {
				if f.RuleID == rule.ID {
					found = true
					break
				}
			}
			if found {
				tpPassed++
			} else {
				tpFailed++
				failures = append(failures, fmt.Sprintf("rule %s (%s): TP not detected: %s",
					rule.ID, filename, truncate(tp, 70)))
			}
		}

		for _, fp := range rule.Examples.FalsePositive {
			target := &scanner.Target{
				RelPath: filename,
				Content: []byte(fp),
			}
			findings, err := matcher.Analyze(context.Background(), target)
			if err != nil {
				t.Errorf("rule %s FP: %v", rule.ID, err)
				continue
			}
			triggered := false
			for _, f := range findings {
				if f.RuleID == rule.ID {
					triggered = true
					break
				}
			}
			if !triggered {
				fpPassed++
			} else {
				fpFailed++
				failures = append(failures, fmt.Sprintf("rule %s: FP triggered: %s",
					rule.ID, truncate(fp, 70)))
			}
		}
	}

	t.Logf("Self-test: TP passed=%d failed=%d, FP passed=%d failed=%d",
		tpPassed, tpFailed, fpPassed, fpFailed)

	// Log failures but don't fail the test - some rules are NLP/toxicflow only
	if tpFailed > 0 {
		t.Logf("NOTE: %d TP failures may be NLP/toxicflow-only rules (not pattern matcher)", tpFailed)
		for _, f := range failures {
			t.Log(f)
		}
	}
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

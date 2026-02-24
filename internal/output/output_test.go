package output_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/garagon/aguara/internal/output"
	"github.com/garagon/aguara/internal/types"
	"github.com/stretchr/testify/require"
)

func TestTerminalFormatterNoFindings(t *testing.T) {
	f := &output.TerminalFormatter{NoColor: true}
	var buf bytes.Buffer
	result := &types.ScanResult{
		Findings:     nil,
		FilesScanned: 5,
		RulesLoaded:  70,
		Target:       "testdata/benign",
	}
	require.NoError(t, f.Format(&buf, result))
	out := buf.String()
	require.Contains(t, out, "No security issues found")
	require.Contains(t, out, "SCAN RESULTS")
	require.Contains(t, out, "5 files scanned")
	require.Contains(t, out, "0 findings")
	require.Contains(t, out, "Target: testdata/benign")
}

func TestTerminalFormatterWithFindings(t *testing.T) {
	f := &output.TerminalFormatter{NoColor: true}
	var buf bytes.Buffer
	result := &types.ScanResult{
		Findings: []types.Finding{
			{
				RuleID:      "TEST_001",
				RuleName:    "Test Rule",
				Severity:    types.SeverityCritical,
				Category:    "test",
				FilePath:    "test.md",
				Line:        5,
				MatchedText: "bad stuff",
				Context: []types.ContextLine{
					{Line: 4, Content: "before", IsMatch: false},
					{Line: 5, Content: "bad stuff here", IsMatch: true},
					{Line: 6, Content: "after", IsMatch: false},
				},
			},
		},
		FilesScanned: 1,
	}

	require.NoError(t, f.Format(&buf, result))
	out := buf.String()
	require.Contains(t, out, "TEST_001")
	require.Contains(t, out, "CRITICAL")
	require.Contains(t, out, "test.md")
	require.Contains(t, out, "SCAN RESULTS")
	require.Contains(t, out, "1 files scanned")
	// Critical finding should show matched text preview
	require.Contains(t, out, "bad stuff")
	require.Contains(t, out, "L5")
}

func TestJSONFormatter(t *testing.T) {
	f := &output.JSONFormatter{}
	var buf bytes.Buffer
	result := &types.ScanResult{
		Findings: []types.Finding{
			{RuleID: "R1", FilePath: "a.md", Line: 1, Severity: types.SeverityHigh},
		},
		FilesScanned: 1,
		RulesLoaded:  10,
	}

	require.NoError(t, f.Format(&buf, result))

	var parsed types.ScanResult
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))
	require.Len(t, parsed.Findings, 1)
	require.Equal(t, "R1", parsed.Findings[0].RuleID)
	require.Equal(t, 1, parsed.FilesScanned)
}

func TestSARIFFormatter(t *testing.T) {
	f := &output.SARIFFormatter{}
	var buf bytes.Buffer
	result := &types.ScanResult{
		Findings: []types.Finding{
			{
				RuleID:      "PROMPT_INJECTION_001",
				RuleName:    "Instruction override attempt",
				Severity:    types.SeverityCritical,
				Category:    "prompt-injection",
				FilePath:    "SKILL.md",
				Line:        10,
				Column:      5,
				MatchedText: "ignore all previous instructions",
			},
			{
				RuleID:      "EXFIL_001",
				RuleName:    "Webhook URL for data exfiltration",
				Severity:    types.SeverityHigh,
				Category:    "exfiltration",
				FilePath:    "config.yaml",
				Line:        3,
				MatchedText: "https://webhook.site/abc123",
			},
		},
		FilesScanned: 2,
		RulesLoaded:  35,
	}

	require.NoError(t, f.Format(&buf, result))

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))

	require.Equal(t, "2.1.0", parsed["version"])
	require.Contains(t, parsed["$schema"], "sarif-schema-2.1.0")

	runs := parsed["runs"].([]any)
	require.Len(t, runs, 1)

	run := runs[0].(map[string]any)
	tool := run["tool"].(map[string]any)
	driver := tool["driver"].(map[string]any)
	require.Equal(t, "aguara", driver["name"])

	rules := driver["rules"].([]any)
	require.Len(t, rules, 2)

	results := run["results"].([]any)
	require.Len(t, results, 2)

	r0 := results[0].(map[string]any)
	require.Equal(t, "PROMPT_INJECTION_001", r0["ruleId"])
	require.Equal(t, "error", r0["level"])

	r1 := results[1].(map[string]any)
	require.Equal(t, "EXFIL_001", r1["ruleId"])
	require.Equal(t, "warning", r1["level"])
}

func TestTerminalFormatterDuration(t *testing.T) {
	f := &output.TerminalFormatter{NoColor: true}
	var buf bytes.Buffer
	result := &types.ScanResult{
		Findings:     nil,
		FilesScanned: 3,
		Duration:     1500 * time.Millisecond,
	}
	require.NoError(t, f.Format(&buf, result))
	out := buf.String()
	// Duration appears in both header and footer
	require.Contains(t, out, "1.50s")
}

func TestTerminalFormatterDashboard(t *testing.T) {
	f := &output.TerminalFormatter{NoColor: true}
	var buf bytes.Buffer
	result := &types.ScanResult{
		Findings: []types.Finding{
			{RuleID: "C1", Severity: types.SeverityCritical, FilePath: "a.md", Line: 1, RuleName: "Crit Rule"},
			{RuleID: "C2", Severity: types.SeverityCritical, FilePath: "a.md", Line: 2, RuleName: "Crit Rule 2"},
			{RuleID: "H1", Severity: types.SeverityHigh, FilePath: "b.md", Line: 1, RuleName: "High Rule"},
			{RuleID: "M1", Severity: types.SeverityMedium, FilePath: "c.md", Line: 1, RuleName: "Med Rule"},
		},
		FilesScanned: 3,
		RulesLoaded:  10,
	}

	require.NoError(t, f.Format(&buf, result))
	out := buf.String()
	// Dashboard should have bar characters and severity counts
	require.Contains(t, out, "\u2588")
	require.Contains(t, out, "\u2591")
	require.Contains(t, out, "CRITICAL")
	require.Contains(t, out, "HIGH")
	require.Contains(t, out, "MEDIUM")
	// Section headers
	require.Contains(t, out, "CRITICAL (2)")
	require.Contains(t, out, "HIGH (1)")
	require.Contains(t, out, "MEDIUM (1)")
}

func TestTerminalFormatterTopFiles(t *testing.T) {
	f := &output.TerminalFormatter{NoColor: true}
	var buf bytes.Buffer
	result := &types.ScanResult{
		Findings: []types.Finding{
			{RuleID: "R1", Severity: types.SeverityHigh, FilePath: "file1.md", Line: 1, RuleName: "Rule 1"},
			{RuleID: "R2", Severity: types.SeverityHigh, FilePath: "file1.md", Line: 2, RuleName: "Rule 2"},
			{RuleID: "R3", Severity: types.SeverityHigh, FilePath: "file1.md", Line: 3, RuleName: "Rule 3"},
			{RuleID: "R4", Severity: types.SeverityMedium, FilePath: "file2.md", Line: 1, RuleName: "Rule 4"},
			{RuleID: "R5", Severity: types.SeverityMedium, FilePath: "file3.md", Line: 1, RuleName: "Rule 5"},
		},
		FilesScanned: 3,
		RulesLoaded:  10,
	}

	require.NoError(t, f.Format(&buf, result))
	out := buf.String()
	require.Contains(t, out, "TOP AFFECTED FILES")
	require.Contains(t, out, "file1.md")
	require.Contains(t, out, "file2.md")
	require.Contains(t, out, "file3.md")
}

func TestSARIFFormatterDuration(t *testing.T) {
	f := &output.SARIFFormatter{}
	var buf bytes.Buffer
	result := &types.ScanResult{
		Findings: []types.Finding{
			{RuleID: "R1", RuleName: "Rule 1", Severity: types.SeverityHigh, FilePath: "a.md", Line: 1},
		},
		FilesScanned: 1,
		Duration:     1500 * time.Millisecond,
	}
	require.NoError(t, f.Format(&buf, result))

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))
	runs := parsed["runs"].([]any)
	run := runs[0].(map[string]any)
	props := run["properties"].(map[string]any)
	require.Equal(t, float64(1500), props["duration_ms"])
}

func TestSARIFFormatterVersion(t *testing.T) {
	original := output.ToolVersion
	defer func() { output.ToolVersion = original }()

	output.ToolVersion = "1.2.3"
	f := &output.SARIFFormatter{}
	var buf bytes.Buffer
	result := &types.ScanResult{
		Findings:     nil,
		FilesScanned: 1,
	}
	require.NoError(t, f.Format(&buf, result))

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))
	runs := parsed["runs"].([]any)
	run := runs[0].(map[string]any)
	tool := run["tool"].(map[string]any)
	driver := tool["driver"].(map[string]any)
	require.Equal(t, "1.2.3", driver["version"])
}

func TestTerminalFormatterVerbose(t *testing.T) {
	f := &output.TerminalFormatter{NoColor: true, Verbose: true}
	var buf bytes.Buffer
	result := &types.ScanResult{
		Findings: []types.Finding{
			{
				RuleID:      "C1",
				RuleName:    "Critical Rule",
				Severity:    types.SeverityCritical,
				Category:    "test",
				Description: "Critical description here",
				FilePath:    "a.md",
				Line:        1,
				MatchedText: "bad",
			},
			{
				RuleID:      "H1",
				RuleName:    "High Rule",
				Severity:    types.SeverityHigh,
				Category:    "test",
				Description: "High description here",
				FilePath:    "b.md",
				Line:        2,
			},
			{
				RuleID:      "M1",
				RuleName:    "Medium Rule",
				Severity:    types.SeverityMedium,
				Category:    "test",
				Description: "Medium description here",
				FilePath:    "c.md",
				Line:        3,
			},
		},
		FilesScanned: 3,
		RulesLoaded:  10,
	}

	require.NoError(t, f.Format(&buf, result))
	out := buf.String()
	// CRITICAL and HIGH descriptions should be visible
	require.Contains(t, out, "Critical description here")
	require.Contains(t, out, "High description here")
	// MEDIUM description should NOT be shown
	require.NotContains(t, out, "Medium description here")
}

func TestTerminalFormatterNonVerboseNoDescription(t *testing.T) {
	f := &output.TerminalFormatter{NoColor: true, Verbose: false}
	var buf bytes.Buffer
	result := &types.ScanResult{
		Findings: []types.Finding{
			{
				RuleID:      "C1",
				RuleName:    "Critical Rule",
				Severity:    types.SeverityCritical,
				Category:    "test",
				Description: "Should not appear",
				FilePath:    "a.md",
				Line:        1,
				MatchedText: "bad",
			},
			{
				RuleID:      "H1",
				RuleName:    "High Rule",
				Severity:    types.SeverityHigh,
				Category:    "test",
				Description: "Should not appear either",
				FilePath:    "b.md",
				Line:        2,
			},
		},
		FilesScanned: 2,
		RulesLoaded:  10,
	}

	require.NoError(t, f.Format(&buf, result))
	out := buf.String()
	require.NotContains(t, out, "Should not appear")
	require.NotContains(t, out, "Should not appear either")
}

func TestMarkdownFormatterNoFindings(t *testing.T) {
	f := &output.MarkdownFormatter{}
	var buf bytes.Buffer
	result := &types.ScanResult{
		Findings:     nil,
		FilesScanned: 5,
		RulesLoaded:  70,
	}
	require.NoError(t, f.Format(&buf, result))
	out := buf.String()
	require.Contains(t, out, "## Aguara Security Scan")
	require.Contains(t, out, "**Passed**")
	require.Contains(t, out, "No security issues found")
}

func TestMarkdownFormatterWithFindings(t *testing.T) {
	f := &output.MarkdownFormatter{}
	var buf bytes.Buffer
	result := &types.ScanResult{
		Findings: []types.Finding{
			{RuleID: "PI_001", RuleName: "Prompt injection", Severity: types.SeverityCritical, Category: "prompt-injection", FilePath: "skill.md", Line: 5},
			{RuleID: "CRED_001", RuleName: "Credential leak", Severity: types.SeverityHigh, Category: "credential-leak", FilePath: "skill.md", Line: 12},
			{RuleID: "EXFIL_001", RuleName: "Data exfiltration", Severity: types.SeverityHigh, Category: "exfiltration", FilePath: "config.yaml", Line: 3},
		},
		FilesScanned: 2,
		RulesLoaded:  138,
		Target:       "testdata/malicious",
	}
	require.NoError(t, f.Format(&buf, result))
	out := buf.String()
	// Header with severity badges
	require.Contains(t, out, "critical")
	require.Contains(t, out, "high")
	// File grouping
	require.Contains(t, out, "`skill.md`")
	require.Contains(t, out, "`config.yaml`")
	// Table structure
	require.Contains(t, out, "| Severity | Rule |")
	require.Contains(t, out, "`PI_001`")
	// Footer
	require.Contains(t, out, "Aguara")
}

func TestMarkdownEscapesPipeChars(t *testing.T) {
	f := &output.MarkdownFormatter{}
	var buf bytes.Buffer
	result := &types.ScanResult{
		Findings: []types.Finding{
			{RuleID: "R1", RuleName: "Rule with | pipe and <angle>", Severity: types.SeverityMedium, FilePath: "a.md", Line: 1},
		},
		FilesScanned: 1,
	}
	require.NoError(t, f.Format(&buf, result))
	out := buf.String()
	// Pipe should be escaped, angle brackets converted
	require.Contains(t, out, "\\|")
	require.Contains(t, out, "&lt;")
	require.Contains(t, out, "&gt;")
}

func TestSARIFFormatterEmpty(t *testing.T) {
	f := &output.SARIFFormatter{}
	var buf bytes.Buffer
	result := &types.ScanResult{
		Findings:     nil,
		FilesScanned: 5,
	}

	require.NoError(t, f.Format(&buf, result))

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))

	require.Equal(t, "2.1.0", parsed["version"])
	runs := parsed["runs"].([]any)
	run := runs[0].(map[string]any)
	// Results should be null/nil (no findings)
	require.Nil(t, run["results"])
}

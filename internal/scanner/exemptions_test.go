package scanner

import (
	"testing"

	"github.com/garagon/aguara/internal/types"
)

func TestApplyToolExemptions_NoToolName(t *testing.T) {
	findings := []Finding{
		{RuleID: "TC-005", Severity: types.SeverityHigh},
	}
	result := applyToolExemptions("", findings, nil)
	if len(result) != 1 {
		t.Errorf("expected 1 finding (no tool name), got %d", len(result))
	}
}

func TestApplyToolExemptions_BuiltinExempt(t *testing.T) {
	findings := []Finding{
		{RuleID: "TC-005", Severity: types.SeverityHigh},
		{RuleID: "PROMPT_INJECTION_001", Severity: types.SeverityHigh},
	}
	result := applyToolExemptions("Edit", findings, nil)
	// TC-005 is exempt for Edit, PROMPT_INJECTION_001 is not
	if len(result) != 1 {
		t.Errorf("expected 1 finding after exemption, got %d", len(result))
	}
	if len(result) > 0 && result[0].RuleID != "PROMPT_INJECTION_001" {
		t.Errorf("expected PROMPT_INJECTION_001 to survive, got %s", result[0].RuleID)
	}
}

func TestApplyToolExemptions_NotExemptForOtherTool(t *testing.T) {
	findings := []Finding{
		{RuleID: "TC-005", Severity: types.SeverityHigh},
	}
	// TC-005 is exempt for Edit but NOT for WebFetch
	result := applyToolExemptions("WebFetch", findings, nil)
	if len(result) != 1 {
		t.Errorf("expected 1 finding (TC-005 not exempt for WebFetch), got %d", len(result))
	}
}

func TestApplyToolExemptions_MCPCFG004ExemptForWebFetch(t *testing.T) {
	findings := []Finding{
		{RuleID: "MCPCFG_004", Severity: types.SeverityMedium},
	}
	result := applyToolExemptions("WebFetch", findings, nil)
	if len(result) != 0 {
		t.Errorf("expected 0 findings (MCPCFG_004 exempt for WebFetch), got %d", len(result))
	}
}

func TestApplyToolExemptions_UserOverrideTakesPrecedence(t *testing.T) {
	findings := []Finding{
		{RuleID: "TC-005", Severity: types.SeverityHigh},
	}
	// User explicitly says TC-005 applies to Edit (overrides built-in exemption)
	userOverrides := map[string]ToolScopedRule{
		"TC-005": {ApplyToTools: []string{"Edit"}},
	}
	result := applyToolExemptions("Edit", findings, userOverrides)
	if len(result) != 1 {
		t.Errorf("expected 1 finding (user override forces TC-005 on Edit), got %d", len(result))
	}
}

func TestApplyToolExemptions_UserExemptTools(t *testing.T) {
	findings := []Finding{
		{RuleID: "PROMPT_INJECTION_001", Severity: types.SeverityHigh},
	}
	// User exempts WebFetch from PROMPT_INJECTION_001
	userOverrides := map[string]ToolScopedRule{
		"PROMPT_INJECTION_001": {ExemptTools: []string{"WebFetch"}},
	}
	result := applyToolExemptions("WebFetch", findings, userOverrides)
	if len(result) != 0 {
		t.Errorf("expected 0 findings (user exempt for WebFetch), got %d", len(result))
	}
}

func TestApplyToolExemptions_UserApplyToToolsNotMatching(t *testing.T) {
	findings := []Finding{
		{RuleID: "TC-005", Severity: types.SeverityHigh},
	}
	// User says TC-005 only applies to Bash, so Edit should skip it
	userOverrides := map[string]ToolScopedRule{
		"TC-005": {ApplyToTools: []string{"Bash"}},
	}
	result := applyToolExemptions("Edit", findings, userOverrides)
	if len(result) != 0 {
		t.Errorf("expected 0 findings (TC-005 only for Bash), got %d", len(result))
	}
}

func TestComputeVerdict(t *testing.T) {
	tests := []struct {
		name     string
		findings []Finding
		want     Verdict
	}{
		{"no findings", nil, VerdictClean},
		{"low severity", []Finding{{Severity: types.SeverityLow}}, VerdictFlag},
		{"medium severity", []Finding{{Severity: types.SeverityMedium}}, VerdictFlag},
		{"high severity", []Finding{{Severity: types.SeverityHigh}}, VerdictBlock},
		{"critical severity", []Finding{{Severity: types.SeverityCritical}}, VerdictBlock},
		{"mixed severities", []Finding{
			{Severity: types.SeverityLow},
			{Severity: types.SeverityCritical},
		}, VerdictBlock},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeVerdict(tt.findings)
			if got != tt.want {
				t.Errorf("computeVerdict() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestApplyProfile_ContentAware(t *testing.T) {
	// Findings without MinimalEnforceRules -> clean
	findings := []Finding{
		{RuleID: "PROMPT_INJECTION_001", Severity: types.SeverityHigh},
	}
	got := applyProfile(ProfileContentAware, findings)
	if got != VerdictClean {
		t.Errorf("content-aware without minimal rules: got %v, want clean", got)
	}

	// Findings WITH MinimalEnforceRules -> block
	findings = append(findings, Finding{RuleID: "TC-001", Severity: types.SeverityHigh})
	got = applyProfile(ProfileContentAware, findings)
	if got != VerdictBlock {
		t.Errorf("content-aware with TC-001: got %v, want block", got)
	}
}

func TestApplyProfile_Minimal(t *testing.T) {
	// Without MinimalEnforceRules -> clean
	findings := []Finding{
		{RuleID: "PROMPT_INJECTION_001", Severity: types.SeverityHigh},
	}
	got := applyProfile(ProfileMinimal, findings)
	if got != VerdictClean {
		t.Errorf("minimal without minimal rules: got %v, want clean", got)
	}

	// With MinimalEnforceRules -> flag (not block)
	findings = append(findings, Finding{RuleID: "TC-003", Severity: types.SeverityHigh})
	got = applyProfile(ProfileMinimal, findings)
	if got != VerdictFlag {
		t.Errorf("minimal with TC-003: got %v, want flag", got)
	}
}

func TestApplyProfile_Strict(t *testing.T) {
	findings := []Finding{
		{RuleID: "PROMPT_INJECTION_001", Severity: types.SeverityHigh},
	}
	got := applyProfile(ProfileStrict, findings)
	if got != VerdictBlock {
		t.Errorf("strict with HIGH finding: got %v, want block", got)
	}
}

func TestIsToolInScope(t *testing.T) {
	tests := []struct {
		name     string
		tool     string
		scoped   ToolScopedRule
		want     bool
	}{
		{"apply_to_tools match", "Bash", ToolScopedRule{ApplyToTools: []string{"Bash"}}, true},
		{"apply_to_tools no match", "Edit", ToolScopedRule{ApplyToTools: []string{"Bash"}}, false},
		{"exempt_tools match", "WebFetch", ToolScopedRule{ExemptTools: []string{"WebFetch"}}, false},
		{"exempt_tools no match", "Edit", ToolScopedRule{ExemptTools: []string{"WebFetch"}}, true},
		{"empty scoped", "Bash", ToolScopedRule{}, true},
		{"case insensitive apply", "bash", ToolScopedRule{ApplyToTools: []string{"Bash"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isToolInScope(tt.tool, tt.scoped)
			if got != tt.want {
				t.Errorf("isToolInScope(%q) = %v, want %v", tt.tool, got, tt.want)
			}
		})
	}
}

func TestContentToolsClassification(t *testing.T) {
	contentTools := []string{"Edit", "Write", "MultiEdit", "Read", "Glob", "Grep", "NotebookEdit"}
	for _, tool := range contentTools {
		if !ContentTools[tool] {
			t.Errorf("%s should be a ContentTool", tool)
		}
	}
	nonContent := []string{"Bash", "WebFetch", "Agent"}
	for _, tool := range nonContent {
		if ContentTools[tool] {
			t.Errorf("%s should NOT be a ContentTool", tool)
		}
	}
}

func TestDevWorkflowToolsClassification(t *testing.T) {
	devTools := []string{"Agent", "TaskCreate", "TaskUpdate", "TaskOutput"}
	for _, tool := range devTools {
		if !DevWorkflowTools[tool] {
			t.Errorf("%s should be a DevWorkflowTool", tool)
		}
	}
}

func TestMinimalEnforceRules(t *testing.T) {
	expected := []string{"TC-001", "TC-003", "TC-006"}
	for _, id := range expected {
		if !MinimalEnforceRules[id] {
			t.Errorf("%s should be a MinimalEnforceRule", id)
		}
	}
	if MinimalEnforceRules["TC-005"] {
		t.Error("TC-005 should NOT be a MinimalEnforceRule")
	}
}

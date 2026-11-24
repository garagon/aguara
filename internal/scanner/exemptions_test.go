package scanner

import (
	"testing"

	"github.com/garagon/aguara/internal/types"
)

func TestApplyToolExemptions_NoToolName(t *testing.T) {
	findings := []Finding{
		{RuleID: "MCPCFG_004", Severity: types.SeverityMedium},
	}
	result := applyToolExemptions("", findings, nil)
	if len(result) != 1 {
		t.Errorf("expected 1 finding (no tool name), got %d", len(result))
	}
}

func TestApplyToolExemptions_BuiltinExempt(t *testing.T) {
	findings := []Finding{
		{RuleID: "MCPCFG_002", Severity: types.SeverityHigh},
		{RuleID: "PROMPT_INJECTION_001", Severity: types.SeverityHigh},
	}
	result := applyToolExemptions("Edit", findings, nil)
	// MCPCFG_002 is exempt for Edit, PROMPT_INJECTION_001 is not
	if len(result) != 1 {
		t.Errorf("expected 1 finding after exemption, got %d", len(result))
	}
	if len(result) > 0 && result[0].RuleID != "PROMPT_INJECTION_001" {
		t.Errorf("expected PROMPT_INJECTION_001 to survive, got %s", result[0].RuleID)
	}
}

func TestApplyToolExemptions_NotExemptForOtherTool(t *testing.T) {
	findings := []Finding{
		{RuleID: "MCPCFG_002", Severity: types.SeverityHigh},
	}
	// MCPCFG_002 is exempt for Edit but NOT for WebFetch
	result := applyToolExemptions("WebFetch", findings, nil)
	if len(result) != 1 {
		t.Errorf("expected 1 finding (MCPCFG_002 not exempt for WebFetch), got %d", len(result))
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

// TestApplyToolExemptions_BuiltinCaseInsensitive: built-in exemptions used to
// compare tool names exactly while user overrides ignored case, so "webfetch"
// kept a finding that "WebFetch" dropped.
func TestApplyToolExemptions_BuiltinCaseInsensitive(t *testing.T) {
	for _, tool := range []string{"WebFetch", "webfetch", "WEBFETCH"} {
		findings := []Finding{{RuleID: "MCPCFG_004", Severity: types.SeverityMedium}}
		if result := applyToolExemptions(tool, findings, nil); len(result) != 0 {
			t.Errorf("tool %q: expected MCPCFG_004 to be exempt, got %d findings", tool, len(result))
		}
	}
}

func TestApplyToolExemptions_UserOverrideTakesPrecedence(t *testing.T) {
	findings := []Finding{
		{RuleID: "MCPCFG_002", Severity: types.SeverityHigh},
	}
	// User explicitly says MCPCFG_002 applies to Edit (overrides built-in exemption)
	userOverrides := map[string]ToolScopedRule{
		"MCPCFG_002": {ApplyToTools: []string{"Edit"}},
	}
	result := applyToolExemptions("Edit", findings, userOverrides)
	if len(result) != 1 {
		t.Errorf("expected 1 finding (user override forces MCPCFG_002 on Edit), got %d", len(result))
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
		{RuleID: "MCPCFG_002", Severity: types.SeverityHigh},
	}
	// User says MCPCFG_002 only applies to Bash, so Edit should skip it
	userOverrides := map[string]ToolScopedRule{
		"MCPCFG_002": {ApplyToTools: []string{"Bash"}},
	}
	result := applyToolExemptions("Edit", findings, userOverrides)
	if len(result) != 0 {
		t.Errorf("expected 0 findings (MCPCFG_002 only for Bash), got %d", len(result))
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

// TestApplyProfileVerdicts locks the profile contract. The relaxed profiles
// used to return clean for every finding outside a hard-coded list of rule
// IDs that the built-in catalog does not contain, so a CRITICAL finding was
// reported clean.
func TestApplyProfileVerdicts(t *testing.T) {
	enforced := map[string]bool{"CUSTOM_ENFORCED_001": true}
	low := Finding{RuleID: "SOME_RULE", Severity: types.SeverityLow}
	medium := Finding{RuleID: "SOME_RULE", Severity: types.SeverityMedium}
	high := Finding{RuleID: "SOME_RULE", Severity: types.SeverityHigh}
	critical := Finding{RuleID: "NLP_OVERRIDE_DANGEROUS", Severity: types.SeverityCritical}
	enforcedLow := Finding{RuleID: "custom_enforced_001", Severity: types.SeverityLow}

	tests := []struct {
		name     string
		profile  ScanProfile
		enforced map[string]bool
		findings []Finding
		want     Verdict
	}{
		{"strict critical", ProfileStrict, nil, []Finding{critical}, VerdictBlock},
		{"strict medium", ProfileStrict, nil, []Finding{medium}, VerdictFlag},
		{"strict ignores enforced list", ProfileStrict, enforced, []Finding{enforcedLow}, VerdictFlag},

		{"content-aware critical", ProfileContentAware, nil, []Finding{critical}, VerdictFlag},
		{"content-aware high", ProfileContentAware, nil, []Finding{high}, VerdictFlag},
		{"content-aware medium only", ProfileContentAware, nil, []Finding{low, medium}, VerdictClean},
		{"content-aware enforced low blocks", ProfileContentAware, enforced, []Finding{enforcedLow}, VerdictBlock},
		{"content-aware enforced plus critical", ProfileContentAware, enforced, []Finding{critical, enforcedLow}, VerdictBlock},
		{"content-aware no findings", ProfileContentAware, enforced, nil, VerdictClean},

		{"minimal critical", ProfileMinimal, nil, []Finding{critical}, VerdictFlag},
		{"minimal high", ProfileMinimal, nil, []Finding{high}, VerdictFlag},
		{"minimal medium only", ProfileMinimal, nil, []Finding{medium}, VerdictClean},
		{"minimal enforced low flags", ProfileMinimal, enforced, []Finding{enforcedLow}, VerdictFlag},
		{"minimal enforced never blocks", ProfileMinimal, enforced, []Finding{critical, enforcedLow}, VerdictFlag},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := applyProfile(tt.profile, tt.findings, tt.enforced); got != tt.want {
				t.Errorf("applyProfile() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestRelaxedProfilesNeverCleanHighOrCritical checks the invariant over every
// profile and every severity: a HIGH or CRITICAL finding is never clean.
func TestRelaxedProfilesNeverCleanHighOrCritical(t *testing.T) {
	for _, profile := range []ScanProfile{ProfileStrict, ProfileContentAware, ProfileMinimal, ScanProfile(99)} {
		for _, sev := range []types.Severity{types.SeverityHigh, types.SeverityCritical} {
			findings := []Finding{{RuleID: "ANY_RULE", Severity: sev}, {RuleID: "OTHER", Severity: types.SeverityLow}}
			if got := applyProfile(profile, findings, nil); got == VerdictClean {
				t.Errorf("profile %d with %s finding returned clean", profile, sev)
			}
		}
	}
}

func TestIsToolInScope(t *testing.T) {
	tests := []struct {
		name   string
		tool   string
		scoped ToolScopedRule
		want   bool
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

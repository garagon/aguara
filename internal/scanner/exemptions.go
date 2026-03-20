package scanner

import "strings"

// BuiltinToolExemptions maps rule IDs to tools where the rule is always a
// false positive by definition. For example, TC-005 (shell injection) in Edit
// is always FP because Edit writes file content, not shell commands.
//
// These exemptions are applied automatically when a tool name is provided via
// ScanContentAs() or WithToolName(). User overrides (apply_to_tools) take
// precedence over built-in exemptions.
var BuiltinToolExemptions = map[string][]string{
	// TC-005: shell metacharacters are normal syntax in file-editing tools
	"TC-005": {"Bash", "Write", "Edit", "MultiEdit", "NotebookEdit", "Agent"},
	// MCPCFG_002: MCP config patterns are normal in file-editing tools
	"MCPCFG_002": {"Bash", "Write", "Edit", "MultiEdit", "NotebookEdit", "Agent"},
	// MCPCFG_004: remote URLs are the purpose of fetch tools
	"MCPCFG_004": {"WebFetch", "Fetch", "WebSearch"},
	// MCPCFG_006: server config patterns are normal in file-editing tools
	"MCPCFG_006": {"Bash", "Write", "Edit", "MultiEdit", "NotebookEdit"},
	// THIRDPARTY_001: third-party content is the purpose of fetch tools
	"THIRDPARTY_001": {"WebFetch", "Fetch", "WebSearch"},
}

// ContentTools are tools that operate on file content where most security
// rules are false positives. Only MinimalEnforceRules are enforced.
var ContentTools = map[string]bool{
	"Edit":         true,
	"Write":        true,
	"MultiEdit":    true,
	"Read":         true,
	"Glob":         true,
	"Grep":         true,
	"NotebookEdit": true,
}

// DevWorkflowTools are tools where NLP-based rules produce false positives
// because task descriptions and commit messages contain descriptive text.
var DevWorkflowTools = map[string]bool{
	"Agent":      true,
	"TaskCreate": true,
	"TaskUpdate": true,
	"TaskOutput": true,
}

// MinimalEnforceRules are the rules that are always enforced regardless of
// scan profile or tool classification. These detect conditions that are
// dangerous in any context.
var MinimalEnforceRules = map[string]bool{
	"TC-001": true, // Path traversal (../../../etc/passwd)
	"TC-003": true, // System directory write (/etc/, /usr/)
	"TC-006": true, // Credentials in tool arguments
}

// ToolScopedRule defines per-rule tool filtering from user configuration.
// ApplyToTools and ExemptTools are mutually exclusive.
type ToolScopedRule struct {
	ApplyToTools []string // only enforce on these tools
	ExemptTools  []string // enforce on all except these
}

// applyToolExemptions removes findings that match built-in tool exemptions.
// User-configured tool-scoped overrides take precedence over built-in exemptions.
func applyToolExemptions(toolName string, findings []Finding, toolScoped map[string]ToolScopedRule) []Finding {
	if toolName == "" {
		return findings
	}
	var kept []Finding
	for _, f := range findings {
		// Check user-configured tool-scoped overrides first (they take precedence)
		if scoped, ok := toolScoped[f.RuleID]; ok {
			if !isToolInScope(toolName, scoped) {
				continue // tool not in scope, skip finding
			}
			kept = append(kept, f)
			continue
		}

		// Check built-in exemptions
		exemptTools, exists := BuiltinToolExemptions[f.RuleID]
		if !exists {
			kept = append(kept, f)
			continue
		}
		if !containsTool(exemptTools, toolName) {
			kept = append(kept, f)
		}
	}
	return kept
}

// isToolInScope returns true if the tool should be scanned for this rule.
func isToolInScope(toolName string, scoped ToolScopedRule) bool {
	if len(scoped.ApplyToTools) > 0 {
		for _, t := range scoped.ApplyToTools {
			if strings.EqualFold(t, toolName) {
				return true
			}
		}
		return false
	}
	if len(scoped.ExemptTools) > 0 {
		for _, t := range scoped.ExemptTools {
			if strings.EqualFold(t, toolName) {
				return false
			}
		}
	}
	return true
}

func containsTool(tools []string, name string) bool {
	for _, t := range tools {
		if t == name {
			return true
		}
	}
	return false
}

// computeVerdict derives a verdict from findings based on severity.
func computeVerdict(findings []Finding) Verdict {
	if len(findings) == 0 {
		return VerdictClean
	}
	for _, f := range findings {
		if f.Severity >= SeverityHigh {
			return VerdictBlock
		}
	}
	return VerdictFlag
}

// applyProfile adjusts the verdict based on the scan profile.
// Findings are always preserved; only the verdict changes.
func applyProfile(profile ScanProfile, findings []Finding) Verdict {
	hasMinimalRule := false
	for _, f := range findings {
		if MinimalEnforceRules[f.RuleID] {
			hasMinimalRule = true
			break
		}
	}

	switch profile {
	case ProfileContentAware:
		if !hasMinimalRule {
			return VerdictClean
		}
		return VerdictBlock
	case ProfileMinimal:
		if !hasMinimalRule {
			return VerdictClean
		}
		return VerdictFlag
	default:
		return computeVerdict(findings)
	}
}

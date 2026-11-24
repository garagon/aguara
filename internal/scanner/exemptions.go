package scanner

import "strings"

// BuiltinToolExemptions maps rule IDs to tools where the rule is always a
// false positive by definition. For example, MCPCFG_004 (remote MCP endpoint)
// in WebFetch is expected because fetching remote URLs is that tool's purpose.
//
// These exemptions are applied automatically when a tool name is provided via
// ScanContentAs() or WithToolName(); tool names match case-insensitively. User
// overrides (apply_to_tools / exempt_tools) take precedence over built-in
// exemptions, and are also how a caller exempts consumer-defined rule IDs.
//
// Keys are upper-case rule IDs that must exist in the built-in catalog; a
// test in internal/rulecatalog fails otherwise. A rule ID that is not in the
// catalog would never match a finding, so the entry would silently do
// nothing.
var BuiltinToolExemptions = map[string][]string{
	// MCPCFG_002: MCP config patterns are normal in file-editing tools
	"MCPCFG_002": {"Bash", "Write", "Edit", "MultiEdit", "NotebookEdit", "Agent"},
	// MCPCFG_004: remote URLs are the purpose of fetch tools
	"MCPCFG_004": {"WebFetch", "Fetch", "WebSearch"},
	// MCPCFG_006: server config patterns are normal in file-editing tools
	"MCPCFG_006": {"Bash", "Write", "Edit", "MultiEdit", "NotebookEdit"},
	// THIRDPARTY_001: third-party content is the purpose of fetch tools
	"THIRDPARTY_001": {"WebFetch", "Fetch", "WebSearch"},
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
		// Check user-configured tool-scoped overrides first (they take precedence).
		// Scanner.SetToolScopedRules stores the keys upper-case.
		if scoped, ok := toolScoped[strings.ToUpper(f.RuleID)]; ok {
			if !isToolInScope(toolName, scoped) {
				continue // tool not in scope, skip finding
			}
			kept = append(kept, f)
			continue
		}

		// Check built-in exemptions
		exemptTools, exists := BuiltinToolExemptions[strings.ToUpper(f.RuleID)]
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

// containsTool reports whether name is in tools, ignoring case, the same way
// user-configured tool scopes match.
func containsTool(tools []string, name string) bool {
	for _, t := range tools {
		if strings.EqualFold(t, name) {
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

// applyProfile adjusts the verdict based on the scan profile. Findings are
// always preserved; only the verdict changes. enforced holds the upper-case
// rule IDs the caller asked the relaxed profiles to keep enforcing.
//
//   - ProfileStrict: computeVerdict (any HIGH or CRITICAL finding blocks).
//   - ProfileContentAware: block when a finding comes from an enforced rule,
//     whatever its severity; otherwise flag when any finding is HIGH or
//     CRITICAL; otherwise clean.
//   - ProfileMinimal: never blocks. Flag when a finding comes from an
//     enforced rule or is HIGH or CRITICAL; otherwise clean.
//
// Neither relaxed profile reports clean while a HIGH or CRITICAL finding
// remains: a rule is only kept out of the verdict when its finding is
// removed, by a disabled rule or a tool exemption that names it.
func applyProfile(profile ScanProfile, findings []Finding, enforced map[string]bool) Verdict {
	if profile != ProfileContentAware && profile != ProfileMinimal {
		return computeVerdict(findings)
	}
	hasEnforced, hasHigh := false, false
	for _, f := range findings {
		if enforced[strings.ToUpper(f.RuleID)] {
			hasEnforced = true
		}
		if f.Severity >= SeverityHigh {
			hasHigh = true
		}
	}
	switch {
	case hasEnforced && profile == ProfileContentAware:
		return VerdictBlock
	case hasEnforced || hasHigh:
		return VerdictFlag
	default:
		return VerdictClean
	}
}

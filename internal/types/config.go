package types

import (
	"fmt"
	"strings"
)

// ConfigProblemKind classifies a problem in caller-supplied rule
// configuration: custom rules, disable lists, rule overrides and the rule
// IDs a scan profile enforces.
type ConfigProblemKind string

const (
	// ConfigProblemInvalidRule means a custom rule could not be compiled
	// (invalid regex, missing field, unknown pattern type, ...) or a rule
	// file could not be used (for example, it exceeds the size limit).
	ConfigProblemInvalidRule ConfigProblemKind = "invalid_rule"
	// ConfigProblemDuplicateRuleID means a custom rule reuses the ID of a
	// built-in rule (pattern or analyzer-emitted) or of another custom rule.
	// IDs are compared case-insensitively.
	ConfigProblemDuplicateRuleID ConfigProblemKind = "duplicate_rule_id"
	// ConfigProblemUnknownRuleID means a disable list, an override or a
	// profile enforcement list names a rule ID that is not in the catalog
	// of loaded rules.
	ConfigProblemUnknownRuleID ConfigProblemKind = "unknown_rule_id"
	// ConfigProblemInvalidSeverity means an override sets a severity that is
	// not one of critical, high, medium, low or info.
	ConfigProblemInvalidSeverity ConfigProblemKind = "invalid_severity"
	// ConfigProblemConflictingOverride means an override sets mutually
	// exclusive fields (ApplyToTools and ExemptTools), or two override keys
	// name the same rule (they differ only in letter case).
	ConfigProblemConflictingOverride ConfigProblemKind = "conflicting_override"
)

// ConfigProblem describes one configuration problem.
type ConfigProblem struct {
	Kind ConfigProblemKind `json:"kind"`
	// RuleID is the rule the problem concerns, as written in the input.
	// Empty when the problem is not tied to one rule.
	RuleID string `json:"rule_id,omitempty"`
	// Source names the input that contains the problem: a rule file path,
	// the option that supplied the value (for example "WithDisabledRules"),
	// or a CLI flag or configuration file.
	Source string `json:"source"`
	// Message is a human-readable description.
	Message string `json:"message"`
}

func (p ConfigProblem) String() string {
	if p.Source == "" {
		return p.Message
	}
	return p.Source + ": " + p.Message
}

// maxProblemsInError bounds Error() for configurations with many problems.
// ConfigError.Problems always holds the complete list.
const maxProblemsInError = 5

// ConfigError reports invalid scanner configuration. Use errors.As to read
// the individual problems.
type ConfigError struct {
	Problems []ConfigProblem
}

func (e *ConfigError) Error() string {
	if len(e.Problems) == 0 {
		return "invalid rule configuration"
	}
	var b strings.Builder
	if len(e.Problems) == 1 {
		b.WriteString("invalid rule configuration: ")
	} else {
		fmt.Fprintf(&b, "invalid rule configuration (%d problems): ", len(e.Problems))
	}
	for i, p := range e.Problems {
		if i == maxProblemsInError {
			fmt.Fprintf(&b, "; and %d more", len(e.Problems)-i)
			break
		}
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(p.String())
	}
	return b.String()
}

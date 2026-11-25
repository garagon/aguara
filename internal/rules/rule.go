// Package rules loads, compiles, and manages YAML-defined detection rules
// with regex/contains patterns, match modes, severity levels, and self-test examples.
package rules

import (
	"regexp"

	"github.com/garagon/aguara/internal/types"
)

// MatchMode determines how multiple patterns are combined.
type MatchMode int

const (
	MatchAny MatchMode = iota // OR — any pattern match triggers a finding
	MatchAll                  // AND — all patterns must match for a finding
)

// PatternType represents the type of a pattern.
type PatternType string

const (
	PatternRegex    PatternType = "regex"
	PatternContains PatternType = "contains"
)

// RawPattern is a single pattern as defined in YAML.
type RawPattern struct {
	Type  PatternType `yaml:"type"`
	Value string      `yaml:"value"`
}

// ExcludeScope selects which lines an exclude pattern is evaluated against.
type ExcludeScope int

const (
	// ExcludeScopeLine evaluates the exclude only against the line or lines
	// the match itself spans. It is the default: an exclude that describes a
	// benign form of the matched text (a comment line, a placeholder value,
	// a logging call) must not be satisfied by a neighbouring line.
	ExcludeScopeLine ExcludeScope = iota
	// ExcludeScopeContext also evaluates the exclude against the
	// ExcludeContextLines lines before the match. It is meant for excludes
	// that identify a documentation section, such as an "## Installation"
	// heading shortly above an install command.
	ExcludeScopeContext
)

// ExcludeContextLines is how many lines before a match a context-scoped
// exclude pattern inspects.
const ExcludeContextLines = 3

// RawExcludePattern is an exclude pattern as defined in YAML. Scope is
// optional: "line" (the default) or "context".
type RawExcludePattern struct {
	Type  PatternType `yaml:"type"`
	Value string      `yaml:"value"`
	Scope string      `yaml:"scope"`
}

// RawExamples contains test examples for rule self-testing.
type RawExamples struct {
	TruePositive  []string `yaml:"true_positive"`
	FalsePositive []string `yaml:"false_positive"`
}

// RawRule is the YAML representation of a detection rule.
type RawRule struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Severity    string   `yaml:"severity"`
	Category    string   `yaml:"category"`
	Targets     []string `yaml:"targets"`
	MatchMode   string   `yaml:"match_mode"`
	// WithinLines, for match_mode: all, requires every pattern to match
	// within a window of that many consecutive lines. Zero (the default)
	// keeps whole-file co-occurrence.
	WithinLines int `yaml:"within_lines"`
	// Sensitive marks rules whose match captures a real secret value
	// (credential read combined with a transmission sink, cross-tool
	// data leak, exfil chain). The scanner copies this flag onto every
	// emitted Finding so RedactSensitiveFindings can scrub MatchedText
	// and the matching context line before JSON/SARIF output.
	Sensitive       bool                `yaml:"sensitive"`
	Patterns        []RawPattern        `yaml:"patterns"`
	ExcludePatterns []RawExcludePattern `yaml:"exclude_patterns"`
	Remediation     string              `yaml:"remediation"`
	Examples        RawExamples         `yaml:"examples"`
}

// CompiledPattern is a pattern ready for matching.
type CompiledPattern struct {
	Type  PatternType
	Regex *regexp.Regexp // set when Type == PatternRegex
	Value string         // set when Type == PatternContains (lowercased)
}

// CompiledExclude is an exclude pattern ready for matching.
type CompiledExclude struct {
	CompiledPattern
	Scope ExcludeScope
}

// CompiledRule is a rule compiled and ready for execution.
type CompiledRule struct {
	ID          string
	Name        string
	Description string
	Severity    types.Severity
	Category    string
	Targets     []string
	// ExcludeTargets are file globs that suppress the rule even when a
	// positive Target (or no target) would otherwise match. Authored in
	// YAML as `!`-prefixed entries in `targets` (e.g. "!package.json").
	// Lets a broadly-scoped rule (targets: *.json) carve out a file that
	// a more specific rule owns, without per-file content heuristics.
	ExcludeTargets []string
	MatchMode      MatchMode
	// WithinLines > 0 bounds a match_mode: all rule to hits that fit in a
	// window of that many consecutive lines; 0 means anywhere in the file.
	WithinLines     int
	Sensitive       bool
	Patterns        []CompiledPattern
	ExcludePatterns []CompiledExclude
	Remediation     string
	Examples        RawExamples
}

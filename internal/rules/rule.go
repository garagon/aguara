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

// RawExamples contains test examples for rule self-testing.
type RawExamples struct {
	TruePositive  []string `yaml:"true_positive"`
	FalsePositive []string `yaml:"false_positive"`
}

// RawRule is the YAML representation of a detection rule.
type RawRule struct {
	ID          string       `yaml:"id"`
	Name        string       `yaml:"name"`
	Description string       `yaml:"description"`
	Severity    string       `yaml:"severity"`
	Category    string       `yaml:"category"`
	Targets     []string     `yaml:"targets"`
	MatchMode   string       `yaml:"match_mode"`
	Patterns    []RawPattern `yaml:"patterns"`
	Examples    RawExamples  `yaml:"examples"`
}

// CompiledPattern is a pattern ready for matching.
type CompiledPattern struct {
	Type  PatternType
	Regex *regexp.Regexp // set when Type == PatternRegex
	Value string         // set when Type == PatternContains (lowercased)
}

// CompiledRule is a rule compiled and ready for execution.
type CompiledRule struct {
	ID          string
	Name        string
	Description string
	Severity    types.Severity
	Category    string
	Targets     []string
	MatchMode   MatchMode
	Patterns    []CompiledPattern
	Examples    RawExamples
}

// Package aguara provides a public API for security scanning of AI agent
// skills and MCP server configurations.
//
// This is the library entry point. For the CLI tool, see cmd/aguara/.
package aguara

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/garagon/aguara/internal/engine/nlp"
	"github.com/garagon/aguara/internal/engine/pattern"
	"github.com/garagon/aguara/internal/engine/toxicflow"
	"github.com/garagon/aguara/internal/rules"
	"github.com/garagon/aguara/internal/rules/builtin"
	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
)

// Re-export core types from internal/types so consumers don't need to
// import internal packages.
type (
	Severity    = types.Severity
	Finding     = types.Finding
	ScanResult  = types.ScanResult
	ContextLine = types.ContextLine
)

const (
	SeverityInfo     = types.SeverityInfo
	SeverityLow      = types.SeverityLow
	SeverityMedium   = types.SeverityMedium
	SeverityHigh     = types.SeverityHigh
	SeverityCritical = types.SeverityCritical
)

// RuleOverride allows changing the severity of a rule or disabling it.
type RuleOverride struct {
	Severity string
	Disabled bool
}

// RuleInfo provides summary metadata about a detection rule.
type RuleInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Category string `json:"category"`
}

// RuleDetail provides full information about a rule, including patterns and examples.
type RuleDetail struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Severity       string   `json:"severity"`
	Category       string   `json:"category"`
	Description    string   `json:"description"`
	Patterns       []string `json:"patterns"`
	TruePositives  []string `json:"true_positives"`
	FalsePositives []string `json:"false_positives"`
}

// Scan scans a file or directory on disk for security issues.
func Scan(ctx context.Context, path string, opts ...Option) (*ScanResult, error) {
	cfg := applyOpts(opts)
	s, compiled, err := buildScanner(cfg)
	if err != nil {
		return nil, err
	}
	result, err := s.Scan(ctx, path)
	if err != nil {
		return nil, err
	}
	result.RulesLoaded = len(compiled)
	return result, nil
}

// ScanContent scans inline content without writing to disk.
// filename is a hint for rule target matching (e.g. "skill.md", "config.json").
func ScanContent(ctx context.Context, content string, filename string, opts ...Option) (*ScanResult, error) {
	if filename == "" {
		filename = "skill.md"
	}
	cfg := applyOpts(opts)
	s, compiled, err := buildScanner(cfg)
	if err != nil {
		return nil, err
	}
	targets := []*scanner.Target{{
		RelPath: filename,
		Content: []byte(content),
	}}
	result, err := s.ScanTargets(ctx, targets)
	if err != nil {
		return nil, err
	}
	result.RulesLoaded = len(compiled)
	return result, nil
}

// ListRules returns all available detection rules.
// Use WithCategory to filter by category.
func ListRules(opts ...Option) []RuleInfo {
	cfg := applyOpts(opts)
	compiled, _ := loadAndCompile(cfg)

	sort.Slice(compiled, func(i, j int) bool {
		return compiled[i].ID < compiled[j].ID
	})

	if cfg.category != "" {
		var filtered []*rules.CompiledRule
		for _, r := range compiled {
			if strings.EqualFold(r.Category, cfg.category) {
				filtered = append(filtered, r)
			}
		}
		compiled = filtered
	}

	infos := make([]RuleInfo, len(compiled))
	for i, r := range compiled {
		infos[i] = RuleInfo{
			ID:       r.ID,
			Name:     r.Name,
			Severity: r.Severity.String(),
			Category: r.Category,
		}
	}
	return infos
}

// ExplainRule returns detailed information about a specific rule.
func ExplainRule(id string, opts ...Option) (*RuleDetail, error) {
	id = strings.ToUpper(strings.TrimSpace(id))
	cfg := applyOpts(opts)
	compiled, _ := loadAndCompile(cfg)

	var found *rules.CompiledRule
	for _, r := range compiled {
		if r.ID == id {
			found = r
			break
		}
	}
	if found == nil {
		return nil, fmt.Errorf("rule %q not found", id)
	}

	patterns := make([]string, len(found.Patterns))
	for i, p := range found.Patterns {
		switch p.Type {
		case rules.PatternRegex:
			patterns[i] = fmt.Sprintf("[regex] %s", p.Regex.String())
		case rules.PatternContains:
			patterns[i] = fmt.Sprintf("[contains] %s", p.Value)
		}
	}

	return &RuleDetail{
		ID:             found.ID,
		Name:           found.Name,
		Severity:       found.Severity.String(),
		Category:       found.Category,
		Description:    found.Description,
		Patterns:       patterns,
		TruePositives:  found.Examples.TruePositive,
		FalsePositives: found.Examples.FalsePositive,
	}, nil
}

// --- internal helpers ---

func applyOpts(opts []Option) *scanConfig {
	cfg := &scanConfig{}
	for _, o := range opts {
		o(cfg)
	}
	return cfg
}

// loadAndCompile loads built-in (and optionally custom) rules, compiles them,
// and applies overrides/filters. Used by all public functions.
func loadAndCompile(cfg *scanConfig) ([]*rules.CompiledRule, error) {
	rawRules, err := rules.LoadFromFS(builtin.FS())
	if err != nil {
		return nil, fmt.Errorf("loading built-in rules: %w", err)
	}

	if cfg.customRulesDir != "" {
		custom, err := rules.LoadFromDir(cfg.customRulesDir)
		if err != nil {
			return nil, fmt.Errorf("loading custom rules from %s: %w", cfg.customRulesDir, err)
		}
		rawRules = append(rawRules, custom...)
	}

	compiled, compileErrs := rules.CompileAll(rawRules)
	for _, e := range compileErrs {
		fmt.Fprintf(os.Stderr, "aguara: warning: %v\n", e)
	}

	if len(cfg.ruleOverrides) > 0 {
		overrides := make(map[string]rules.RuleOverride, len(cfg.ruleOverrides))
		for id, ovr := range cfg.ruleOverrides {
			overrides[id] = rules.RuleOverride{Severity: ovr.Severity, Disabled: ovr.Disabled}
		}
		var overrideErrs []error
		compiled, overrideErrs = rules.ApplyOverrides(compiled, overrides)
		for _, e := range overrideErrs {
			fmt.Fprintf(os.Stderr, "aguara: warning: %v\n", e)
		}
	}

	if len(cfg.disabledRules) > 0 {
		disabled := make(map[string]bool, len(cfg.disabledRules))
		for _, id := range cfg.disabledRules {
			disabled[strings.TrimSpace(id)] = true
		}
		compiled = rules.FilterByIDs(compiled, disabled)
	}

	return compiled, nil
}

// buildScanner creates a fully wired Scanner with all standard analyzers.
func buildScanner(cfg *scanConfig) (*scanner.Scanner, []*rules.CompiledRule, error) {
	compiled, err := loadAndCompile(cfg)
	if err != nil {
		return nil, nil, err
	}

	s := scanner.New(cfg.workers)
	s.SetMinSeverity(cfg.minSeverity)
	if len(cfg.ignorePatterns) > 0 {
		s.SetIgnorePatterns(cfg.ignorePatterns)
	}

	s.RegisterAnalyzer(pattern.NewMatcher(compiled))
	s.RegisterAnalyzer(nlp.NewInjectionAnalyzer())
	s.RegisterAnalyzer(toxicflow.New())

	return s, compiled, nil
}

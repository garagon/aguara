// Package aguara provides a public API for security scanning of AI agent
// skills and MCP server configurations.
//
// This is the library entry point. For the CLI tool, see cmd/aguara/.
package aguara

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/text/unicode/norm"

	"github.com/garagon/aguara/discover"
	"github.com/garagon/aguara/internal/engine/ci"
	"github.com/garagon/aguara/internal/engine/nlp"
	"github.com/garagon/aguara/internal/engine/pattern"
	"github.com/garagon/aguara/internal/engine/rugpull"
	"github.com/garagon/aguara/internal/engine/toxicflow"
	"github.com/garagon/aguara/internal/rules"
	"github.com/garagon/aguara/internal/rules/builtin"
	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/state"
	"github.com/garagon/aguara/internal/types"
)

// Re-export core types from internal/types so consumers don't need to
// import internal packages.
type (
	Severity        = types.Severity
	Finding         = types.Finding
	ScanResult      = types.ScanResult
	ContextLine     = types.ContextLine
	Verdict         = types.Verdict
	ScanProfile     = types.ScanProfile
	DeduplicateMode = types.DeduplicateMode
)

const (
	SeverityInfo     = types.SeverityInfo
	SeverityLow      = types.SeverityLow
	SeverityMedium   = types.SeverityMedium
	SeverityHigh     = types.SeverityHigh
	SeverityCritical = types.SeverityCritical

	VerdictClean = types.VerdictClean
	VerdictFlag  = types.VerdictFlag
	VerdictBlock = types.VerdictBlock

	ProfileStrict       = types.ProfileStrict
	ProfileContentAware = types.ProfileContentAware
	ProfileMinimal      = types.ProfileMinimal

	DeduplicateFull         = types.DeduplicateFull
	DeduplicateSameRuleOnly = types.DeduplicateSameRuleOnly
)

// Re-export discover types so consumers don't need a separate import.
type (
	DiscoverResult   = discover.Result
	DiscoveredServer = discover.MCPServer
	DiscoveredClient = discover.ClientResult
)

// Discover finds all MCP client configurations on the local machine.
func Discover() (*DiscoverResult, error) {
	return discover.Scan()
}

// RuleOverride allows changing the severity of a rule, disabling it, or
// restricting it to specific tools.
type RuleOverride struct {
	Severity     string
	Disabled     bool
	ApplyToTools []string // only enforce on these tools (mutually exclusive with ExemptTools)
	ExemptTools  []string // enforce on all tools except these
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
	Remediation    string   `json:"remediation,omitempty"`
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
	if cfg.redact {
		redactCredentialFindings(result.Findings)
	}
	return result, nil
}

// ScanContent scans inline content without writing to disk.
// filename is a hint for rule target matching (e.g. "skill.md", "config.json").
// Content is NFKC-normalized before scanning to prevent Unicode evasion attacks.
func ScanContent(ctx context.Context, content string, filename string, opts ...Option) (*ScanResult, error) {
	return scanContentInternal(ctx, content, filename, "", opts)
}

// ScanContentAs scans inline content with tool context for false-positive reduction.
// toolName identifies the tool that generated the content (e.g. "Bash", "Edit", "WebFetch").
// When provided, built-in tool exemptions and scan profiles can reduce false positives.
// Content is NFKC-normalized before scanning to prevent Unicode evasion attacks.
func ScanContentAs(ctx context.Context, content string, filename string, toolName string, opts ...Option) (*ScanResult, error) {
	return scanContentInternal(ctx, content, filename, toolName, opts)
}

func scanContentInternal(ctx context.Context, content string, filename string, toolName string, opts []Option) (*ScanResult, error) {
	if filename == "" {
		filename = "skill.md"
	}
	// NFKC normalization prevents Unicode evasion (e.g. fullwidth "Ｉｇｎｏｒｅ" → "Ignore")
	content = norm.NFKC.String(content)

	cfg := applyOpts(opts)
	// Explicit toolName parameter takes precedence over WithToolName option
	if toolName != "" {
		cfg.toolName = toolName
	}
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
	if cfg.redact {
		redactCredentialFindings(result.Findings)
	}
	return result, nil
}

// ListRules returns all available detection rules.
// Use WithCategory to filter by category.
func ListRules(opts ...Option) []RuleInfo {
	cfg := applyOpts(opts)
	cr, _ := loadAndCompile(cfg)
	if cr == nil {
		return nil
	}
	compiled := cr.compiled

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
	cr, _ := loadAndCompile(cfg)
	if cr == nil {
		return nil, fmt.Errorf("rule %q not found (rules failed to load)", id)
	}
	compiled := cr.compiled

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
		Remediation:    found.Remediation,
		Patterns:       patterns,
		TruePositives:  found.Examples.TruePositive,
		FalsePositives: found.Examples.FalsePositive,
	}, nil
}

// Scanner holds a pre-compiled scanner that can be reused across scans.
// Build once with NewScanner at startup, then call ScanContent/Scan for
// each request. The compiled rules, regex patterns, and Aho-Corasick
// automatons are built once and shared, eliminating per-request overhead.
// Thread-safe: multiple goroutines can call methods concurrently.
type Scanner struct {
	compiled   []*rules.CompiledRule
	toolScoped map[string]scanner.ToolScopedRule
	matcher    *pattern.Matcher
	cfg        *scanConfig
}

// NewScanner creates a pre-compiled scanner with the given options.
// Call once at startup, reuse for all subsequent scans.
func NewScanner(opts ...Option) (*Scanner, error) {
	cfg := applyOpts(opts)
	cr, err := loadAndCompile(cfg)
	if err != nil {
		return nil, err
	}
	return &Scanner{
		compiled:   cr.compiled,
		toolScoped: cr.toolScopedRules,
		matcher:    pattern.NewMatcher(cr.compiled),
		cfg:        cfg,
	}, nil
}

// ScanContent scans inline content using the pre-compiled scanner.
// Content is NFKC-normalized before scanning to prevent Unicode evasion.
func (sc *Scanner) ScanContent(ctx context.Context, content string, filename string) (*ScanResult, error) {
	return sc.scanContent(ctx, content, filename, "")
}

// ScanContentAs scans inline content with tool context for false-positive reduction.
func (sc *Scanner) ScanContentAs(ctx context.Context, content string, filename string, toolName string) (*ScanResult, error) {
	return sc.scanContent(ctx, content, filename, toolName)
}

func (sc *Scanner) scanContent(ctx context.Context, content string, filename string, toolName string) (*ScanResult, error) {
	if filename == "" {
		filename = "skill.md"
	}
	content = norm.NFKC.String(content)

	s, err := sc.buildInternalScanner(toolName)
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
	result.RulesLoaded = len(sc.compiled)
	if sc.cfg.redact {
		redactCredentialFindings(result.Findings)
	}
	return result, nil
}

// Scan scans a file or directory on disk using the pre-compiled scanner.
func (sc *Scanner) Scan(ctx context.Context, path string) (*ScanResult, error) {
	s, err := sc.buildInternalScanner("")
	if err != nil {
		return nil, err
	}
	result, err := s.Scan(ctx, path)
	if err != nil {
		return nil, err
	}
	result.RulesLoaded = len(sc.compiled)
	if sc.cfg.redact {
		redactCredentialFindings(result.Findings)
	}
	return result, nil
}

// ListRules returns all rules loaded in this scanner, sorted by ID.
func (sc *Scanner) ListRules() []RuleInfo {
	compiled := make([]*rules.CompiledRule, len(sc.compiled))
	copy(compiled, sc.compiled)
	sort.Slice(compiled, func(i, j int) bool {
		return compiled[i].ID < compiled[j].ID
	})
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
func (sc *Scanner) ExplainRule(id string) (*RuleDetail, error) {
	id = strings.ToUpper(strings.TrimSpace(id))
	for _, r := range sc.compiled {
		if r.ID == id {
			patterns := make([]string, len(r.Patterns))
			for i, p := range r.Patterns {
				switch p.Type {
				case rules.PatternRegex:
					patterns[i] = fmt.Sprintf("[regex] %s", p.Regex.String())
				case rules.PatternContains:
					patterns[i] = fmt.Sprintf("[contains] %s", p.Value)
				}
			}
			return &RuleDetail{
				ID:             r.ID,
				Name:           r.Name,
				Severity:       r.Severity.String(),
				Category:       r.Category,
				Description:    r.Description,
				Remediation:    r.Remediation,
				Patterns:       patterns,
				TruePositives:  r.Examples.TruePositive,
				FalsePositives: r.Examples.FalsePositive,
			}, nil
		}
	}
	return nil, fmt.Errorf("rule %q not found", id)
}

// RulesLoaded returns the number of compiled rules in this scanner.
func (sc *Scanner) RulesLoaded() int {
	return len(sc.compiled)
}

// buildInternalScanner creates a lightweight scanner.Scanner reusing the
// cached pattern matcher. NLP/ToxicFlow analyzers and the cross-file
// accumulator are created fresh (they're stateless and cheap).
func (sc *Scanner) buildInternalScanner(toolName string) (*scanner.Scanner, error) {
	s := scanner.New(sc.cfg.workers)
	s.SetMinSeverity(sc.cfg.minSeverity)
	if len(sc.cfg.ignorePatterns) > 0 {
		s.SetIgnorePatterns(sc.cfg.ignorePatterns)
	}
	if sc.cfg.maxFileSize > 0 {
		s.SetMaxFileSize(sc.cfg.maxFileSize)
	}
	tn := sc.cfg.toolName
	if toolName != "" {
		tn = toolName
	}
	if tn != "" {
		s.SetToolName(tn)
	}
	if sc.cfg.scanProfile != ProfileStrict {
		s.SetScanProfile(sc.cfg.scanProfile)
	}
	if len(sc.toolScoped) > 0 {
		s.SetToolScopedRules(sc.toolScoped)
	}
	if len(sc.cfg.disabledRules) > 0 {
		s.SetDisabledRules(sc.cfg.disabledRules)
	}
	if sc.cfg.deduplicateMode != 0 {
		s.SetDeduplicateMode(sc.cfg.deduplicateMode)
	}

	// Reuse pre-compiled pattern matcher (the expensive part: regex + AC automaton)
	s.RegisterAnalyzer(sc.matcher)
	// CI trust analyzer parses workflow YAML — runs before toxicflow so its
	// chain findings can be deduped/correlated alongside leaf signals.
	s.RegisterAnalyzer(ci.New())
	// NLP and ToxicFlow are stateless, cheap to instantiate
	s.RegisterAnalyzer(nlp.NewInjectionAnalyzer())
	s.RegisterAnalyzer(toxicflow.New())
	s.SetCrossFileAccumulator(toxicflow.NewCrossFileAnalyzer())

	// Rug-pull: fresh state store per scan for thread safety
	if sc.cfg.stateDir != "" {
		statePath := filepath.Join(sc.cfg.stateDir, "state.json")
		store := state.New(statePath)
		if err := store.Load(); err != nil {
			return nil, fmt.Errorf("loading state from %s: %w", statePath, err)
		}
		s.RegisterAnalyzer(rugpull.New(store))
		s.SetStateStore(store)
	}

	return s, nil
}

// --- internal helpers ---

func applyOpts(opts []Option) *scanConfig {
	// Redaction is opt-out: by default, credential-leak findings have their
	// matched text scrubbed before they leave the library. Callers that need
	// the raw match must explicitly pass WithRedaction(false).
	cfg := &scanConfig{redact: true}
	for _, o := range opts {
		o(cfg)
	}
	return cfg
}

// redactCredentialFindings scrubs matched text and context for findings in the
// credential-leak category. Detecting a secret and then writing it verbatim to
// terminal, JSON, SARIF, or -o output defeats the purpose of detection: the
// finding artifact becomes a second copy of the secret, often with weaker
// access controls than the original file (CI logs, GitHub Code Scanning,
// Slack notifications, etc.).
//
// Delegates to types.RedactCredentialFindings so the CLI and library share a
// single implementation. Only credential-leak findings are altered.
func redactCredentialFindings(findings []Finding) {
	types.RedactCredentialFindings(findings)
}

type compileResult struct {
	compiled         []*rules.CompiledRule
	toolScopedRules  map[string]scanner.ToolScopedRule
}

// loadAndCompile loads built-in (and optionally custom) rules, compiles them,
// and applies overrides/filters. Used by all public functions.
func loadAndCompile(cfg *scanConfig) (*compileResult, error) {
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
	_ = compileErrs // non-fatal: invalid rules are skipped

	var toolScoped map[string]scanner.ToolScopedRule
	if len(cfg.ruleOverrides) > 0 {
		overrides := make(map[string]rules.RuleOverride, len(cfg.ruleOverrides))
		for id, ovr := range cfg.ruleOverrides {
			overrides[id] = rules.RuleOverride{
				Severity:     ovr.Severity,
				Disabled:     ovr.Disabled,
				ApplyToTools: ovr.ApplyToTools,
				ExemptTools:  ovr.ExemptTools,
			}
		}
		compiled, _ = rules.ApplyOverrides(compiled, overrides)
		// Collect tool-scoped overrides for runtime filtering
		for id, ovr := range overrides {
			if len(ovr.ApplyToTools) > 0 || len(ovr.ExemptTools) > 0 {
				if toolScoped == nil {
					toolScoped = make(map[string]scanner.ToolScopedRule)
				}
				toolScoped[id] = scanner.ToolScopedRule{
					ApplyToTools: ovr.ApplyToTools,
					ExemptTools:  ovr.ExemptTools,
				}
			}
		}
	}

	if len(cfg.disabledRules) > 0 {
		disabled := make(map[string]bool, len(cfg.disabledRules))
		for _, id := range cfg.disabledRules {
			disabled[strings.TrimSpace(id)] = true
		}
		compiled = rules.FilterByIDs(compiled, disabled)
	}

	return &compileResult{compiled: compiled, toolScopedRules: toolScoped}, nil
}

// buildScanner creates a fully wired Scanner with all standard analyzers.
func buildScanner(cfg *scanConfig) (*scanner.Scanner, []*rules.CompiledRule, error) {
	cr, err := loadAndCompile(cfg)
	if err != nil {
		return nil, nil, err
	}

	s := scanner.New(cfg.workers)
	s.SetMinSeverity(cfg.minSeverity)
	if len(cfg.ignorePatterns) > 0 {
		s.SetIgnorePatterns(cfg.ignorePatterns)
	}
	if cfg.maxFileSize > 0 {
		s.SetMaxFileSize(cfg.maxFileSize)
	}
	if cfg.toolName != "" {
		s.SetToolName(cfg.toolName)
	}
	if cfg.scanProfile != ProfileStrict {
		s.SetScanProfile(cfg.scanProfile)
	}
	if len(cr.toolScopedRules) > 0 {
		s.SetToolScopedRules(cr.toolScopedRules)
	}
	if len(cfg.disabledRules) > 0 {
		s.SetDisabledRules(cfg.disabledRules)
	}
	if cfg.deduplicateMode != 0 {
		s.SetDeduplicateMode(cfg.deduplicateMode)
	}

	s.RegisterAnalyzer(pattern.NewMatcher(cr.compiled))
	s.RegisterAnalyzer(ci.New())
	s.RegisterAnalyzer(nlp.NewInjectionAnalyzer())
	s.RegisterAnalyzer(toxicflow.New())
	s.SetCrossFileAccumulator(toxicflow.NewCrossFileAnalyzer())

	// Enable rug-pull detection when stateDir is provided
	if cfg.stateDir != "" {
		statePath := filepath.Join(cfg.stateDir, "state.json")
		store := state.New(statePath)
		if err := store.Load(); err != nil {
			return nil, nil, fmt.Errorf("loading state from %s: %w", statePath, err)
		}
		s.RegisterAnalyzer(rugpull.New(store))
		s.SetStateStore(store)
	}

	return s, cr.compiled, nil
}

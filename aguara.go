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
	"github.com/garagon/aguara/internal/engine"
	"github.com/garagon/aguara/internal/engine/pattern"
	"github.com/garagon/aguara/internal/engine/rugpull"
	"github.com/garagon/aguara/internal/rulecatalog"
	"github.com/garagon/aguara/internal/rulemeta"
	"github.com/garagon/aguara/internal/rules"
	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/state"
	"github.com/garagon/aguara/internal/types"
)

// ErrIncompleteScan indicates that a target could not be read or analyzed,
// or that file discovery failed. Scans return no result in this case.
// Use errors.Is to distinguish it from findings or caller cancellation.
var ErrIncompleteScan = scanner.ErrIncompleteScan

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

	DecisionImpactContext = types.DecisionImpactContext
	DecisionImpactReview  = types.DecisionImpactReview
)

// Configuration problems. NewScanner, the package-level scan functions and
// ListRulesE return a *ConfigError for invalid rule configuration; each
// ConfigProblem names the kind, rule ID, source and a message.
type (
	ConfigError       = types.ConfigError
	ConfigProblem     = types.ConfigProblem
	ConfigProblemKind = types.ConfigProblemKind
)

const (
	ConfigProblemInvalidRule         = types.ConfigProblemInvalidRule
	ConfigProblemDuplicateRuleID     = types.ConfigProblemDuplicateRuleID
	ConfigProblemUnknownRuleID       = types.ConfigProblemUnknownRuleID
	ConfigProblemInvalidSeverity     = types.ConfigProblemInvalidSeverity
	ConfigProblemConflictingOverride = types.ConfigProblemConflictingOverride
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
//
// Analyzer is empty for pattern-matcher rules driven by YAML and
// set to the analyzer name for analyzer-emitted rules (ci-trust,
// pkgmeta, jsrisk, nlp, toxicflow). The omitempty tag keeps JSON
// output compact for the common case.
type RuleInfo struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Severity       string `json:"severity"`
	Category       string `json:"category"`
	Analyzer       string `json:"analyzer,omitempty"`
	DecisionImpact string `json:"decision_impact"`
}

// RuleDetail provides full information about a rule, including patterns and examples.
//
// Analyzer is empty for pattern-matcher rules driven by YAML and
// set to the analyzer name for analyzer-emitted rules. Patterns,
// TruePositives, and FalsePositives are typically empty for
// analyzer-emitted rules because the analyzer logic itself is the
// pattern.
type RuleDetail struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Severity       string   `json:"severity"`
	Category       string   `json:"category"`
	Analyzer       string   `json:"analyzer,omitempty"`
	DecisionImpact string   `json:"decision_impact"`
	Description    string   `json:"description"`
	Remediation    string   `json:"remediation,omitempty"`
	Patterns       []string `json:"patterns"`
	TruePositives  []string `json:"true_positives"`
	FalsePositives []string `json:"false_positives"`
}

// Scan scans a file or directory on disk for security issues. Target-owned
// .aguaraignore and inline suppression directives are ignored by default
// because public API callers commonly scan repositories they do not trust.
// Pass WithTrustedTargetPolicy only when the caller owns those controls.
func Scan(ctx context.Context, path string, opts ...Option) (*ScanResult, error) {
	cfg := applyOpts(opts)
	if cfg.targetPolicy == nil {
		enabled := false
		cfg.targetPolicy = &enabled
	}
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

// ScanContent scans inline content without writing to disk. Inline suppression
// directives are ignored by default because content passed through this API is
// commonly the object of a trust decision. Pass WithTrustedTargetPolicy only
// for content whose suppression directives are controlled by the caller.
// filename is a hint for rule target matching (e.g. "skill.md", "config.json").
// Text detection uses NFKC normalization; npm manifest parsing retains original
// syntax so normalization cannot change JSON member identity.
func ScanContent(ctx context.Context, content string, filename string, opts ...Option) (*ScanResult, error) {
	return scanContentInternal(ctx, content, filename, "", opts)
}

// ScanContentAs scans inline content with tool context for false-positive reduction.
// toolName identifies the tool that generated the content (e.g. "Bash", "Edit", "WebFetch").
// When provided, built-in tool exemptions and scan profiles can reduce false positives.
// Text detection uses NFKC normalization; npm manifest parsing retains original syntax.
func ScanContentAs(ctx context.Context, content string, filename string, toolName string, opts ...Option) (*ScanResult, error) {
	return scanContentInternal(ctx, content, filename, toolName, opts)
}

func scanContentInternal(ctx context.Context, content string, filename string, toolName string, opts []Option) (*ScanResult, error) {
	if filename == "" {
		filename = "skill.md"
	}
	cfg := applyOpts(opts)
	if cfg.targetPolicy == nil {
		enabled := false
		cfg.targetPolicy = &enabled
	}
	// Explicit toolName parameter takes precedence over WithToolName option
	if toolName != "" {
		cfg.toolName = toolName
	}
	s, compiled, err := buildScanner(cfg)
	if err != nil {
		return nil, err
	}
	targets := []*scanner.Target{inlineTarget(content, filename)}
	result, err := s.ScanTargets(ctx, targets)
	if err != nil {
		return nil, err
	}
	result.RulesLoaded = len(compiled)
	return result, nil
}

// ListRules returns all available detection rules. Includes BOTH
// YAML-driven pattern rules AND analyzer-emitted rules (ci-trust,
// pkgmeta, jsrisk, nlp, toxicflow, rugpull), so a finding's
// RuleID always resolves through this function. WithCategory
// filters; WithDisabledRules and WithRuleOverrides drop / mutate
// rules so a policy UI built on top of ListRules sees the same
// set the scanner will consult.
//
// ListRules returns nil when the options are invalid (for example, a
// custom rules directory that cannot be read or a custom rule that does
// not compile). Use ListRulesE to get the reason.
func ListRules(opts ...Option) []RuleInfo {
	infos, err := ListRulesE(opts...)
	if err != nil {
		return nil
	}
	return infos
}

// ListRulesE is ListRules with an error result. Invalid rule configuration
// is reported as a *ConfigError (unless WithLenientConfig is set); a custom
// rules directory that cannot be loaded is reported as an ordinary error.
func ListRulesE(opts ...Option) ([]RuleInfo, error) {
	cfg := applyOpts(opts)
	res, err := resolveConfig(cfg)
	if err != nil {
		return nil, err
	}
	cat := res.Catalog(cfg.category)
	infos := make([]RuleInfo, len(cat))
	for i, r := range cat {
		infos[i] = ruleInfoFromMetadata(r)
	}
	return infos, nil
}

// ExplainRule returns detailed information about a specific rule.
// Resolves both YAML rules and analyzer-emitted rules (a finding
// with RuleID "JS_DNS_TXT_EXFIL_001" or "GHA_PWN_REQUEST_001"
// can be explained the same way as a pattern rule).
//
// Only WithCustomRules and WithLenientConfig affect the lookup. An unknown
// ID returns an error matching errors.Is(err, ErrRuleNotFound). Problems
// loading the custom rules are returned as such (a *ConfigError for a rule
// that does not compile or reuses an ID), not reported as "not found".
func ExplainRule(id string, opts ...Option) (*RuleDetail, error) {
	id = rulecatalog.CanonicalID(id)
	cfg := applyOpts(opts)
	res, err := resolveConfig(&scanConfig{
		customRulesDirs: cfg.customRulesDirs,
		lenientConfig:   cfg.lenientConfig,
	})
	if err != nil {
		return nil, err
	}
	for _, r := range res.Catalog("") {
		if strings.EqualFold(r.ID, id) {
			return ruleDetailFromMetadata(r), nil
		}
	}
	return nil, &ruleNotFoundError{id: id}
}

// ErrRuleNotFound is matched (with errors.Is) by the error ExplainRule and
// Scanner.ExplainRule return for a rule ID that is not in the catalog.
var ErrRuleNotFound = rulecatalog.ErrRuleNotFound

type ruleNotFoundError struct{ id string }

func (e *ruleNotFoundError) Error() string { return fmt.Sprintf("rule %q not found", e.id) }
func (e *ruleNotFoundError) Unwrap() error { return ErrRuleNotFound }

// Scanner holds a pre-compiled scanner that can be reused across scans.
// Build once with NewScanner at startup, then call ScanContent/Scan for
// each request. The compiled rules, regex patterns, and Aho-Corasick
// automatons are built once and shared, eliminating per-request overhead.
// Thread-safe: multiple goroutines can call methods concurrently.
type Scanner struct {
	resolution *rulecatalog.Resolution
	catalog    []rulemeta.Rule
	matcher    *pattern.Matcher
	cfg        *scanConfig
}

// NewScanner creates a pre-compiled scanner with the given options. Reusable
// scanners treat target-owned ignore policy as untrusted by default. Call once
// at startup and reuse for all subsequent scans.
//
// Invalid rule configuration (a custom rule that does not compile or reuses
// an existing rule ID, an unknown rule ID in WithDisabledRules or
// WithRuleOverrides, an invalid override severity, conflicting tool scopes)
// returns a *ConfigError listing every problem; use errors.As to read them.
// WithLenientConfig skips such problems instead.
func NewScanner(opts ...Option) (*Scanner, error) {
	cfg := applyOpts(opts)
	if cfg.targetPolicy == nil {
		enabled := false
		cfg.targetPolicy = &enabled
	}
	res, err := resolveConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Scanner{
		resolution: res,
		catalog:    res.Catalog(""),
		matcher:    pattern.NewMatcher(res.Compiled),
		cfg:        cfg,
	}, nil
}

// ConfigProblems returns the configuration problems this scanner skipped
// because WithLenientConfig was set. Without that option NewScanner fails on
// any problem, so the result is empty.
func (sc *Scanner) ConfigProblems() []ConfigProblem {
	return append([]ConfigProblem(nil), sc.resolution.Problems...)
}

// ScanContent scans inline content using the pre-compiled scanner.
// Text detection uses NFKC normalization; npm manifest parsing retains original syntax.
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
	s, err := sc.buildInternalScanner(toolName)
	if err != nil {
		return nil, err
	}
	targets := []*scanner.Target{inlineTarget(content, filename)}
	result, err := s.ScanTargets(ctx, targets)
	if err != nil {
		return nil, err
	}
	result.RulesLoaded = len(sc.resolution.Compiled)
	return result, nil
}

func inlineTarget(content, filename string) *scanner.Target {
	// Text detectors keep their existing NFKC view. Preserve the original only
	// when it differs, so manifest parsing cannot merge distinct JSON keys.
	target := &scanner.Target{RelPath: filename, Content: []byte(content)}
	if normalized := norm.NFKC.String(content); normalized != content {
		target.OriginalContent = target.Content
		target.Content = []byte(normalized)
	}
	return target
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
	result.RulesLoaded = len(sc.resolution.Compiled)
	return result, nil
}

// ListRules returns every pattern and analyzer rule active in this scanner,
// sorted by ID.
func (sc *Scanner) ListRules() []RuleInfo {
	infos := make([]RuleInfo, len(sc.catalog))
	for i, r := range sc.catalog {
		infos[i] = ruleInfoFromMetadata(r)
	}
	return infos
}

// ExplainRule returns detailed information about a pattern or analyzer rule
// active in this scanner.
func (sc *Scanner) ExplainRule(id string) (*RuleDetail, error) {
	id = rulecatalog.CanonicalID(id)
	for _, r := range sc.catalog {
		if strings.EqualFold(r.ID, id) {
			return ruleDetailFromMetadata(r), nil
		}
	}
	return nil, &ruleNotFoundError{id: id}
}

func ruleInfoFromMetadata(r rulemeta.Rule) RuleInfo {
	return RuleInfo{
		ID:             r.ID,
		Name:           r.Name,
		Severity:       r.Severity,
		Category:       r.Category,
		Analyzer:       r.Analyzer,
		DecisionImpact: r.DecisionImpact,
	}
}

func ruleDetailFromMetadata(r rulemeta.Rule) *RuleDetail {
	return &RuleDetail{
		ID:             r.ID,
		Name:           r.Name,
		Severity:       r.Severity,
		Category:       r.Category,
		Analyzer:       r.Analyzer,
		DecisionImpact: r.DecisionImpact,
		Description:    r.Description,
		Remediation:    r.Remediation,
		Patterns:       append([]string(nil), r.Patterns...),
		TruePositives:  append([]string(nil), r.TruePositives...),
		FalsePositives: append([]string(nil), r.FalsePositives...),
	}
}

// RulesLoaded returns the number of compiled rules in this scanner.
func (sc *Scanner) RulesLoaded() int {
	return len(sc.resolution.Compiled)
}

// buildInternalScanner creates a lightweight scanner.Scanner reusing the
// cached pattern matcher. NLP/ToxicFlow analyzers and the cross-file
// accumulator are created fresh (they're stateless and cheap).
func (sc *Scanner) buildInternalScanner(toolName string) (*scanner.Scanner, error) {
	tn := sc.cfg.toolName
	if toolName != "" {
		tn = toolName
	}
	return newPipeline(sc.cfg, sc.resolution, sc.matcher, tn)
}

// newPipeline wires a scanner.Scanner for one scan: the given pattern
// matcher first, then the default analyzer set owned by internal/engine (so
// the CLI and both library paths always register the same pipeline), then
// rug-pull when a state directory is configured.
func newPipeline(cfg *scanConfig, res *rulecatalog.Resolution, matcher *pattern.Matcher, toolName string) (*scanner.Scanner, error) {
	s := scanner.New(cfg.workers)
	s.SetMinSeverity(cfg.minSeverity)
	s.SetRedaction(cfg.redact)
	if cfg.targetPolicy != nil {
		s.SetProjectPolicyEnabled(*cfg.targetPolicy)
	}
	if len(cfg.ignorePatterns) > 0 {
		s.SetIgnorePatterns(cfg.ignorePatterns)
	}
	if cfg.maxFileSize > 0 {
		s.SetMaxFileSize(cfg.maxFileSize)
	}
	if toolName != "" {
		s.SetToolName(toolName)
	}
	if cfg.scanProfile != ProfileStrict {
		s.SetScanProfile(cfg.scanProfile)
	}
	if toolScoped := res.ToolScopedRules(); len(toolScoped) > 0 {
		s.SetToolScopedRules(toolScoped)
	}
	if len(res.Disabled) > 0 {
		s.SetDisabledRules(res.Disabled)
	}
	if cfg.deduplicateMode != 0 {
		s.SetDeduplicateMode(cfg.deduplicateMode)
	}

	// The matcher holds the expensive part (regex + Aho-Corasick automaton)
	// and is safe to share across scans.
	s.RegisterAnalyzer(matcher)
	engine.RegisterDefaults(s, res.Overrides)

	// Rug-pull: fresh state store per scan for thread safety
	if cfg.stateDir != "" {
		statePath := filepath.Join(cfg.stateDir, "state.json")
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

// resolveConfig loads and validates the rule configuration in cfg. Problems
// are returned as a *ConfigError unless the caller opted into lenient
// handling, in which case they stay readable on the resolution.
func resolveConfig(cfg *scanConfig) (*rulecatalog.Resolution, error) {
	res, err := rulecatalog.Resolve(cfg.ruleInput())
	if err != nil {
		return nil, err
	}
	if len(res.Problems) > 0 && !cfg.lenientConfig {
		return nil, &ConfigError{Problems: append([]ConfigProblem(nil), res.Problems...)}
	}
	return res, nil
}

// ruleInput describes the caller's rule options for validation. Override
// keys are sorted so problems are reported in a stable order.
func (c *scanConfig) ruleInput() rulecatalog.Input {
	in := rulecatalog.Input{CustomRulesDirs: c.customRulesDirs}
	for _, id := range c.disabledRules {
		in.Disabled = append(in.Disabled, rulecatalog.Ref{ID: id, Source: "WithDisabledRules"})
	}
	ids := make([]string, 0, len(c.ruleOverrides))
	for id := range c.ruleOverrides {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		ovr := c.ruleOverrides[id]
		in.Overrides = append(in.Overrides, rulecatalog.OverrideRef{
			ID:     id,
			Source: "WithRuleOverrides",
			Override: rules.RuleOverride{
				Severity:     ovr.Severity,
				Disabled:     ovr.Disabled,
				ApplyToTools: ovr.ApplyToTools,
				ExemptTools:  ovr.ExemptTools,
			},
		})
	}
	return in
}

// buildScanner creates a fully wired Scanner for the package-level scan
// functions.
func buildScanner(cfg *scanConfig) (*scanner.Scanner, []*rules.CompiledRule, error) {
	res, err := resolveConfig(cfg)
	if err != nil {
		return nil, nil, err
	}
	s, err := newPipeline(cfg, res, pattern.NewMatcher(res.Compiled), cfg.toolName)
	if err != nil {
		return nil, nil, err
	}
	return s, res.Compiled, nil
}

package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/garagon/aguara/internal/meta"
	"github.com/garagon/aguara/internal/rulemeta"
	"github.com/garagon/aguara/internal/types"
)

// CrossFileAccumulator can accumulate per-file data and finalize cross-file findings.
type CrossFileAccumulator interface {
	Accumulate(relPath string, content string)
	Finalize() []Finding
}

// CrossFileFindingObserver is an optional extension of CrossFileAccumulator.
// When the configured accumulator also implements it, the scanner passes each
// file's findings to ObserveFindings after every registered per-file analyzer
// has run on that file. The findings have already passed inline suppression
// (when project policy is trusted), the disabled-rule filter, severity
// overrides and tool exemptions, the same steps and order the report applies
// first, so an observer sees each finding's reported severity. Later report
// steps (dedup, scoring, the minimum-severity filter) are not applied.
//
// Findings returned by Finalize are never observed, so a cross-file finding
// cannot feed back into the correlation that produced it. ObserveFindings can
// be called concurrently from scanner workers; implementations must not
// modify the slice or retain it after returning.
type CrossFileFindingObserver interface {
	ObserveFindings(relPath string, findings []Finding)
}

// StateSaver can persist state after a scan completes.
type StateSaver interface {
	Save() error
}

// Scanner orchestrates the scanning process.
type Scanner struct {
	analyzers            []Analyzer
	workers              int
	minSeverity          Severity
	ignorePatterns       []string
	maxFileSize          int64
	onProgress           func(current, total int)
	toolName             string
	scanProfile          ScanProfile
	profileEnforced      map[string]bool
	toolScopedRules      map[string]ToolScopedRule
	disabledRules        map[string]bool
	severityOverrides    map[string]Severity
	deduplicateMode      DeduplicateMode
	crossFileAccumulator CrossFileAccumulator
	stateStore           StateSaver
	projectPolicyEnabled bool
	outputFiles          []string
	redact               bool
}

// New creates a new Scanner with the given number of workers.
// If workers <= 0, it defaults to runtime.NumCPU().
func New(workers int) *Scanner {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	return &Scanner{
		workers:              workers,
		projectPolicyEnabled: true,
	}
}

// RegisterAnalyzer adds an analyzer to the scanner pipeline.
func (s *Scanner) RegisterAnalyzer(a Analyzer) {
	s.analyzers = append(s.analyzers, a)
}

// SetMinSeverity sets the minimum severity for reported findings.
func (s *Scanner) SetMinSeverity(sev Severity) {
	s.minSeverity = sev
}

// SetRedaction enables result sanitization while retaining redaction evidence
// from findings removed by presentation filters. Internal callers opt in;
// public library and CLI builders enable it unless explicitly disabled.
func (s *Scanner) SetRedaction(enabled bool) {
	s.redact = enabled
}

// SetIgnorePatterns sets additional file ignore patterns from config. The
// slice is copied, so later changes by the caller have no effect.
func (s *Scanner) SetIgnorePatterns(patterns []string) {
	s.ignorePatterns = append([]string(nil), patterns...)
}

// SetProjectPolicyEnabled controls whether files being scanned may suppress
// findings through .aguaraignore and inline aguara-ignore directives. It is
// enabled by default for backwards-compatible local scans. Consumers that
// inspect untrusted repositories or content should disable it.
func (s *Scanner) SetProjectPolicyEnabled(enabled bool) {
	s.projectPolicyEnabled = enabled
}

// SetOutputFiles names files this scan writes, such as its report or
// baseline. A directory walk or path list never scans them, so a report an
// earlier run of the same command left in the target cannot change the
// result. Files named directly to Scan are scanned as before.
func (s *Scanner) SetOutputFiles(paths []string) {
	s.outputFiles = append([]string(nil), paths...)
}

// SetMaxFileSize sets the maximum file size for scanning.
// Zero means use the default (50 MB).
func (s *Scanner) SetMaxFileSize(size int64) {
	s.maxFileSize = size
}

// SetProgressFunc sets an optional callback invoked after each file is scanned.
// The callback receives the number of files processed so far and the total count.
// It may be called from multiple goroutines concurrently.
func (s *Scanner) SetProgressFunc(fn func(current, total int)) {
	s.onProgress = fn
}

// SetToolName sets the tool context for tool-aware false-positive reduction.
func (s *Scanner) SetToolName(name string) {
	s.toolName = name
}

// SetScanProfile sets the enforcement profile.
func (s *Scanner) SetScanProfile(profile ScanProfile) {
	s.scanProfile = profile
}

// SetProfileEnforcedRules sets the rule IDs (case-insensitive) whose
// findings block under every profile except ProfileMinimal, which flags
// them, regardless of severity. The caller validates the IDs; see
// applyProfile for the verdicts.
func (s *Scanner) SetProfileEnforcedRules(ids []string) {
	if len(ids) == 0 {
		s.profileEnforced = nil
		return
	}
	m := make(map[string]bool, len(ids))
	for _, id := range ids {
		if id = strings.ToUpper(strings.TrimSpace(id)); id != "" {
			m[id] = true
		}
	}
	s.profileEnforced = m
}

// SetToolScopedRules sets per-rule tool filtering from user configuration.
// Rule IDs are matched case-insensitively.
func (s *Scanner) SetToolScopedRules(rules map[string]ToolScopedRule) {
	if len(rules) == 0 {
		s.toolScopedRules = nil
		return
	}
	normalized := make(map[string]ToolScopedRule, len(rules))
	for id, scoped := range rules {
		normalized[strings.ToUpper(strings.TrimSpace(id))] = scoped
	}
	s.toolScopedRules = normalized
}

// IsRuleDisabled reports the scanner-wide rule-ID filter to analyzers that
// would otherwise perform work (or report a budget error) for a disabled rule.
func (s *Scanner) IsRuleDisabled(id string) bool {
	return s.disabledRules[strings.ToUpper(strings.TrimSpace(id))]
}

// SetDisabledRules suppresses findings whose RuleID is present in ids. This
// covers both pattern rules (which already get filtered out of the compiled
// rule list upstream) and analyzer-emitted IDs that the compiled-list filter
// never sees: ci-trust (GHA_*), toxicflow (TOXIC_*), rugpull (RUGPULL_001),
// NLP injection, and any cross-file finding. The filter runs in postProcess
// before tool exemptions and dedup so disabled findings cost nothing
// downstream.
func (s *Scanner) SetDisabledRules(ids []string) {
	if len(ids) == 0 {
		s.disabledRules = nil
		return
	}
	m := make(map[string]bool, len(ids))
	for _, id := range ids {
		id = strings.ToUpper(strings.TrimSpace(id))
		if id != "" {
			m[id] = true
		}
	}
	if len(m) == 0 {
		s.disabledRules = nil
		return
	}
	s.disabledRules = m
}

// SetSeverityOverrides replaces the severity of every finding whose rule ID
// (case-insensitive) has an entry, whichever analyzer emitted it. As with a
// pattern rule's own severity, a finding inside a Markdown code block in
// ordinary documentation is lowered one level from the override; in
// SKILL.md and agent instruction files (types.IsAgentDirectiveFile) it keeps
// the override's full severity. Overrides apply after the
// disabled-rule filter and before tool exemptions, dedup, scoring and the
// minimum-severity filter, so they behave exactly like a changed rule
// severity.
func (s *Scanner) SetSeverityOverrides(overrides map[string]Severity) {
	if len(overrides) == 0 {
		s.severityOverrides = nil
		return
	}
	m := make(map[string]Severity, len(overrides))
	for id, sev := range overrides {
		m[strings.ToUpper(strings.TrimSpace(id))] = sev
	}
	s.severityOverrides = m
}

// SetDeduplicateMode sets how findings on the same line are deduplicated.
func (s *Scanner) SetDeduplicateMode(mode DeduplicateMode) {
	s.deduplicateMode = mode
}

// SetCrossFileAccumulator sets the cross-file analyzer for directory scans.
func (s *Scanner) SetCrossFileAccumulator(cfa CrossFileAccumulator) {
	s.crossFileAccumulator = cfa
}

// SetStateStore sets a state saver to persist state after scan completes.
func (s *Scanner) SetStateStore(store StateSaver) {
	s.stateStore = store
}

// Scan performs a full scan of the given path. The path can be a directory
// (walked recursively) or a single file.
func (s *Scanner) Scan(ctx context.Context, root string) (*ScanResult, error) {
	// Check if root is a single file (not a directory).
	info, err := os.Stat(root)
	if err != nil {
		return nil, IncompleteScanError("inspect target", root, "", err)
	}
	if !info.IsDir() {
		// Single-file scan: use the filename as RelPath so target-filtered
		// rules (e.g. "*.md", "*.json") can match correctly.
		targets := []*Target{{
			Path:        root,
			RelPath:     filepath.Base(root),
			MaxFileSize: s.maxFileSize,
		}}
		return s.ScanTargets(ctx, targets)
	}

	// Directory scan: discover all files recursively.
	// The explicit root may be a symlink; child symlinks remain excluded.
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, IncompleteScanError("resolve root", root, "", err)
	}
	discovery := &TargetDiscovery{
		IgnorePatterns:    s.ignorePatterns,
		MaxFileSize:       s.maxFileSize,
		IgnoreProjectFile: !s.projectPolicyEnabled,
		OutputFiles:       s.outputFiles,
	}
	targets, err := discovery.Discover(resolvedRoot)
	if err != nil {
		return nil, err
	}
	// Analyzers also use the caller's logical path (e.g. .github/workflows).
	// Resolving traversal must not erase that identity through a symlink.
	for _, target := range targets {
		target.Path = filepath.Join(root, target.RelPath)
	}

	result, err := s.ScanTargets(ctx, targets)
	if err != nil {
		return nil, err
	}
	if discovery.ExcludedByIgnoreFile > 0 {
		result.TargetPolicy.IgnoreFile = filepath.Join(root, ".aguaraignore")
	}
	result.TargetPolicy.IgnorePatternExclusions = discovery.ExcludedByCallerPatterns
	result.TargetPolicy.IgnorePatterns = discovery.PatternUses(root)
	result.TargetPolicy.SkippedOutputFiles = discovery.SkippedOutputs
	return result, nil
}

// ScanPaths scans several files and directories as one scan rooted at
// root, a directory that contains all of them. Paths are relative to the
// working directory, as typed; findings report paths relative to root.
// Ignore patterns, including root's .aguaraignore when project policy is
// enabled, apply to every path, files named directly included. Cross-file
// correlation sees only the files of this scan, grouped by their directory
// relative to root. It also returns the symbolic links it was given, which
// are not followed.
func (s *Scanner) ScanPaths(ctx context.Context, root string, paths []string) (*ScanResult, []string, error) {
	discovery := &TargetDiscovery{
		IgnorePatterns:    s.ignorePatterns,
		MaxFileSize:       s.maxFileSize,
		IgnoreProjectFile: !s.projectPolicyEnabled,
		OutputFiles:       s.outputFiles,
	}
	targets, err := discovery.DiscoverPaths(root, paths)
	if err != nil {
		return nil, nil, err
	}
	for _, target := range targets {
		target.Path = filepath.Join(root, target.RelPath)
	}
	result, err := s.ScanTargets(ctx, targets)
	if err != nil {
		return nil, nil, err
	}
	if discovery.ExcludedByIgnoreFile > 0 {
		result.TargetPolicy.IgnoreFile = filepath.Join(root, ".aguaraignore")
	}
	result.TargetPolicy.IgnorePatternExclusions = discovery.ExcludedByCallerPatterns
	result.TargetPolicy.IgnorePatterns = discovery.PatternUses(root)
	result.TargetPolicy.SkippedOutputFiles = discovery.SkippedOutputs
	return result, discovery.SkippedLinks, nil
}

// ScanTargets runs the scanner pipeline on a pre-built list of targets.
func (s *Scanner) ScanTargets(ctx context.Context, targets []*Target) (*ScanResult, error) {
	start := time.Now()

	// Fill MaxFileSize for targets that don't have it set.
	if s.maxFileSize > 0 {
		for _, t := range targets {
			if t.MaxFileSize <= 0 {
				t.MaxFileSize = s.maxFileSize
			}
		}
	}

	// Fan-out files to workers
	fileCh := make(chan *Target, len(targets))
	for _, t := range targets {
		fileCh <- t
	}
	close(fileCh)

	var (
		mu        sync.Mutex
		findings  []Finding
		wg        sync.WaitGroup
		processed atomic.Int32
		redaction types.RedactionPlan
		scanErr   error
		failures  int
		// suppressedBy records files whose inline directives removed
		// findings, so callers can report that target policy applied.
		suppressedBy = map[string]bool{}
	)
	recordFailure := func(err error) {
		mu.Lock()
		defer mu.Unlock()
		failures++
		// Keep one deterministic diagnostic instead of retaining an unbounded
		// collection of errors from an attacker-controlled directory.
		if scanErr == nil || err.Error() < scanErr.Error() {
			scanErr = err
		}
	}

	total := len(targets)
	for range s.workers {
		wg.Go(func() {
			for target := range fileCh {
				if ctx.Err() != nil {
					return
				}
				if err := target.LoadContent(); err != nil {
					recordFailure(IncompleteScanError("read target", target.RelPath, "", err))
					continue
				}
				if s.redact {
					mu.Lock()
					redaction.AddContent(target.RelPath, target.StringContent())
					mu.Unlock()
				}
				// Accumulate content for cross-file analysis
				if s.crossFileAccumulator != nil {
					s.crossFileAccumulator.Accumulate(target.RelPath, target.StringContent())
				}
				var ignoreIndex map[int]map[string]bool
				if s.projectPolicyEnabled {
					ignoreIndex = buildIgnoreIndex(parseIgnoreDirectives(target.Content))
				}
				var fileFindings []Finding
				for _, analyzer := range s.analyzers {
					if ctx.Err() != nil {
						return
					}
					results, err := analyzer.Analyze(ctx, target)
					if err != nil {
						recordFailure(IncompleteScanError("analyze target", target.RelPath, analyzer.Name(), err))
						continue
					}
					if len(results) > 0 {
						if s.redact {
							mu.Lock()
							redaction.AddFindings(results)
							mu.Unlock()
						}
						if ignoreIndex != nil {
							var kept []Finding
							for _, f := range results {
								if !isIgnoredByInline(ignoreIndex, f.Line, f.RuleID) {
									kept = append(kept, f)
								}
							}
							if len(kept) < len(results) {
								mu.Lock()
								suppressedBy[target.RelPath] = true
								mu.Unlock()
							}
							results = kept
						}
						if len(results) > 0 {
							fileFindings = append(fileFindings, results...)
							mu.Lock()
							findings = append(findings, results...)
							mu.Unlock()
						}
					}
				}
				s.observeFileFindings(target.RelPath, fileFindings)
				if s.onProgress != nil {
					n := int(processed.Add(1))
					s.onProgress(n, total)
				}
			}
		})
	}

	wg.Wait()

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if scanErr != nil {
		return nil, fmt.Errorf("%w; %d failed operation(s)", scanErr, failures)
	}

	// Cross-file analysis: finalize after all workers complete
	if s.crossFileAccumulator != nil {
		crossFileFindings := s.crossFileAccumulator.Finalize()
		if s.redact {
			redaction.AddFindings(crossFileFindings)
		}
		findings = append(findings, crossFileFindings...)
	}

	for i := range findings {
		findings[i].DecisionImpact = rulemeta.DecisionImpactFor(findings[i].RuleID)
	}
	findings = s.postProcess(findings)

	verdict := computeVerdict(findings)
	if (s.scanProfile != ProfileStrict || len(s.profileEnforced) > 0) && len(findings) > 0 {
		verdict = applyProfile(s.scanProfile, findings, s.profileEnforced)
	}

	// Persist state (rug-pull hashes) if configured
	if s.stateStore != nil {
		_ = s.stateStore.Save() // best-effort; scan results are still valid
	}

	riskScore := meta.ComputeRiskScore(findings)
	if s.redact {
		redaction.Apply(findings)
	}

	// Normalize the empty-result shape so the JSON output reads
	// `"findings": []` instead of `"findings": null` on a clean scan.
	// postProcess returns nil on several happy paths (no input, all
	// filtered out by --disable-rule, all dropped by min-severity);
	// downstream JSON consumers expect the array shape regardless.
	if findings == nil {
		findings = []Finding{}
	}

	var policy types.TargetPolicyUse
	for path := range suppressedBy {
		policy.InlineSuppressed = append(policy.InlineSuppressed, path)
	}
	sort.Strings(policy.InlineSuppressed)

	return &ScanResult{
		Findings:     findings,
		FilesScanned: len(targets),
		Verdict:      verdict,
		RiskScore:    riskScore,
		ToolName:     s.toolName,
		Duration:     time.Since(start),
		TargetPolicy: policy,
	}, nil
}

// observeFileFindings hands one file's per-file findings to an accumulator
// that implements CrossFileFindingObserver. Disabled rules, severity
// overrides and tool exemptions are applied first, in postProcess order, so
// a correlation never cites a finding the caller removed or a severity the
// report does not show. The observed findings are copies: overriding their
// severity does not touch the findings postProcess later receives.
func (s *Scanner) observeFileFindings(relPath string, fileFindings []Finding) {
	observer, ok := s.crossFileAccumulator.(CrossFileFindingObserver)
	if !ok || len(fileFindings) == 0 {
		return
	}
	kept := make([]Finding, 0, len(fileFindings))
	for _, f := range fileFindings {
		if s.disabledRules[strings.ToUpper(f.RuleID)] {
			continue
		}
		s.applySeverityOverride(&f)
		kept = append(kept, f)
	}
	kept = applyToolExemptions(s.toolName, kept, s.toolScopedRules)
	if len(kept) > 0 {
		observer.ObserveFindings(relPath, kept)
	}
}

// applySeverityOverride sets f's severity to the override configured for its
// rule (canonical upper-cased ID), if there is one. Same contract as the
// pattern matcher: only ordinary documentation lowers a fenced finding one
// level; in SKILL.md and agent instruction files the fenced block is what
// the agent runs. The result depends only on the override and where the
// finding is, never on its current severity, so a value that already
// carries the override is unchanged by a second application.
func (s *Scanner) applySeverityOverride(f *Finding) {
	sev, ok := s.severityOverrides[strings.ToUpper(f.RuleID)]
	if !ok {
		return
	}
	if f.InCodeBlock && !types.IsAgentDirectiveFile(f.FilePath) {
		sev = types.DowngradeSeverity(sev)
	}
	f.Severity = sev
}

// postProcess deduplicates, scores, correlates, filters, and sorts findings.
func (s *Scanner) postProcess(findings []Finding) []Finding {
	if len(findings) == 0 {
		return nil
	}

	// Disabled-rule filter runs first: it is the cheapest definitive drop
	// (user explicitly silenced these IDs) and ensures analyzer-emitted IDs
	// (GHA_*, TOXIC_*, RUGPULL_001, etc.) receive the same suppression the
	// compiled rule list already gives pattern rules.
	if len(s.disabledRules) > 0 {
		kept := findings[:0]
		for _, f := range findings {
			if !s.disabledRules[strings.ToUpper(f.RuleID)] {
				kept = append(kept, f)
			}
		}
		findings = kept
		if len(findings) == 0 {
			return nil
		}
	}

	if len(s.severityOverrides) > 0 {
		for i := range findings {
			s.applySeverityOverride(&findings[i])
		}
	}

	// Apply tool exemptions before dedup/scoring (removes definite false positives)
	if s.toolName != "" {
		findings = applyToolExemptions(s.toolName, findings, s.toolScopedRules)
	}
	findings = meta.DeduplicateWithMode(findings, s.deduplicateMode)
	findings = meta.ScoreFindings(findings)
	groups := meta.Correlate(findings)
	findings = flattenGroups(groups)
	findings = meta.AdjustConfidence(findings)

	if s.minSeverity > SeverityInfo {
		var filtered []Finding
		for _, f := range findings {
			if f.Severity >= s.minSeverity {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	// Dedup and correlation iterate maps, so the slice arrives in a
	// different order on every run. The comparator is a total order on
	// post-dedup findings, which makes the result independent of that
	// order (and of worker scheduling).
	SortFindings(findings)

	return findings
}

// SortFindings orders findings the way every scan result is ordered: by
// severity (highest first), then file, line, column, rule ID and analyzer.
// Callers that merge several results (such as scan --auto) use it to keep
// the same order.
func SortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		return findingLess(findings[i], findings[j])
	})
}

// findingLess orders findings by severity (highest first), then file, line,
// column, rule ID and analyzer. The remaining fields only break ties between
// findings that dedup would normally have merged.
func findingLess(a, b Finding) bool {
	if a.Severity != b.Severity {
		return a.Severity > b.Severity
	}
	if a.FilePath != b.FilePath {
		return a.FilePath < b.FilePath
	}
	if a.Line != b.Line {
		return a.Line < b.Line
	}
	if a.Column != b.Column {
		return a.Column < b.Column
	}
	if a.RuleID != b.RuleID {
		return a.RuleID < b.RuleID
	}
	if a.Analyzer != b.Analyzer {
		return a.Analyzer < b.Analyzer
	}
	if a.MatchedText != b.MatchedText {
		return a.MatchedText < b.MatchedText
	}
	return a.RuleName < b.RuleName
}

func flattenGroups(groups []meta.CorrelationGroup) []Finding {
	var result []Finding
	for _, g := range groups {
		result = append(result, g.Findings...)
	}
	return result
}

package scanner

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/garagon/aguara/internal/meta"
)

// Scanner orchestrates the scanning process.
type Scanner struct {
	analyzers      []Analyzer
	workers        int
	minSeverity    Severity
	ignorePatterns []string
}

// New creates a new Scanner with the given number of workers.
// If workers <= 0, it defaults to runtime.NumCPU().
func New(workers int) *Scanner {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	return &Scanner{
		workers: workers,
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

// SetIgnorePatterns sets additional file ignore patterns from config.
func (s *Scanner) SetIgnorePatterns(patterns []string) {
	s.ignorePatterns = patterns
}

// Scan performs a full scan of the given path. The path can be a directory
// (walked recursively) or a single file.
func (s *Scanner) Scan(ctx context.Context, root string) (*ScanResult, error) {
	// Check if root is a single file (not a directory).
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		// Single-file scan: use the filename as RelPath so target-filtered
		// rules (e.g. "*.md", "*.json") can match correctly.
		targets := []*Target{{
			Path:    root,
			RelPath: filepath.Base(root),
		}}
		return s.ScanTargets(ctx, targets)
	}

	// Directory scan: discover all files recursively.
	discovery := &TargetDiscovery{IgnorePatterns: s.ignorePatterns}
	targets, err := discovery.Discover(root)
	if err != nil {
		return nil, err
	}

	return s.ScanTargets(ctx, targets)
}

// ScanTargets runs the scanner pipeline on a pre-built list of targets.
func (s *Scanner) ScanTargets(ctx context.Context, targets []*Target) (*ScanResult, error) {
	start := time.Now()

	// Fan-out files to workers
	fileCh := make(chan *Target, len(targets))
	for _, t := range targets {
		fileCh <- t
	}
	close(fileCh)

	var (
		mu       sync.Mutex
		findings []Finding
		wg       sync.WaitGroup
	)

	for range s.workers {
		wg.Go(func() {
			for target := range fileCh {
				if ctx.Err() != nil {
					return
				}
				if err := target.LoadContent(); err != nil {
					continue
				}
				for _, analyzer := range s.analyzers {
					if ctx.Err() != nil {
						return
					}
					results, err := analyzer.Analyze(ctx, target)
					if err != nil {
						continue
					}
					if len(results) > 0 {
						mu.Lock()
						findings = append(findings, results...)
						mu.Unlock()
					}
				}
			}
		})
	}

	wg.Wait()

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	findings = s.postProcess(findings)

	return &ScanResult{
		Findings:     findings,
		FilesScanned: len(targets),
		Duration:     time.Since(start),
	}, nil
}

// postProcess deduplicates, scores, correlates, filters, and sorts findings.
func (s *Scanner) postProcess(findings []Finding) []Finding {
	findings = meta.Deduplicate(findings)
	findings = meta.ScoreFindings(findings)
	groups := meta.Correlate(findings)
	findings = flattenGroups(groups)

	if s.minSeverity > SeverityInfo {
		var filtered []Finding
		for _, f := range findings {
			if f.Severity >= s.minSeverity {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity > findings[j].Severity
		}
		if findings[i].FilePath != findings[j].FilePath {
			return findings[i].FilePath < findings[j].FilePath
		}
		return findings[i].Line < findings[j].Line
	})

	return findings
}

func flattenGroups(groups []meta.CorrelationGroup) []Finding {
	var result []Finding
	for _, g := range groups {
		result = append(result, g.Findings...)
	}
	return result
}

// Package engine is the single source of truth for the default
// analyzer set. Every entry point that builds a scanner (the CLI's
// scan command and both library constructors in the root package)
// registers the same analyzers in the same pipeline order through
// RegisterDefaults, and the rule catalog (explain / list-rules)
// aggregates every analyzer's metadata through RuleMetadata.
//
// Before this package existed, adding one analyzer meant editing four
// registration sites plus the catalog by hand, and a missed site meant
// the CLI and the library silently disagreed about what a scan runs.
// Now an analyzer is added exactly once, here.
//
// Two analyzers intentionally stay caller-wired and are NOT part of
// RegisterDefaults:
//
//   - the pattern matcher, because it is built from compiled YAML rules
//     (and the library path reuses a pre-compiled matcher, the
//     expensive part: regex + Aho-Corasick automaton);
//   - rug-pull, because it only joins when the caller provides a state
//     store (--monitor on the CLI, WithStateDir in the library).
//
// Their metadata is still aggregated here (rug-pull through
// RuleMetadata; pattern rules come from the YAML catalog, not from an
// analyzer).
package engine

import (
	"github.com/garagon/aguara/internal/engine/agentpolicy"
	"github.com/garagon/aguara/internal/engine/ci"
	"github.com/garagon/aguara/internal/engine/jsrisk"
	"github.com/garagon/aguara/internal/engine/nlp"
	"github.com/garagon/aguara/internal/engine/pkgmeta"
	"github.com/garagon/aguara/internal/engine/pnpmpolicy"
	"github.com/garagon/aguara/internal/engine/pyrisk"
	"github.com/garagon/aguara/internal/engine/rsbuild"
	"github.com/garagon/aguara/internal/engine/rugpull"
	"github.com/garagon/aguara/internal/engine/toxicflow"
	"github.com/garagon/aguara/internal/rulemeta"
	"github.com/garagon/aguara/internal/scanner"
)

// DefaultAnalyzers returns fresh instances of the stateless analyzers
// every scan runs, in pipeline order. The order is part of the
// contract: ci-trust runs before toxicflow so its chain findings can be
// deduped and correlated alongside leaf signals, and the slice runs
// after the caller-registered pattern matcher and before the optional
// rug-pull analyzer.
func DefaultAnalyzers() []scanner.Analyzer {
	return []scanner.Analyzer{
		ci.New(),
		pkgmeta.New(),
		jsrisk.New(),
		pyrisk.New(),
		rsbuild.New(),
		pnpmpolicy.New(),
		agentpolicy.New(),
		nlp.NewInjectionAnalyzer(),
		toxicflow.New(),
	}
}

// RegisterDefaults registers the default analyzer set plus the
// cross-file correlation accumulator on s. Callers register the pattern
// matcher before this and the optional rug-pull analyzer after it.
func RegisterDefaults(s *scanner.Scanner) {
	for _, a := range DefaultAnalyzers() {
		s.RegisterAnalyzer(a)
	}
	s.SetCrossFileAccumulator(toxicflow.NewCrossFileAnalyzer())
}

// RuleMetadata returns the catalog entries for every analyzer-emitted
// rule, including rug-pull (whose analyzer is registered conditionally
// at runtime but whose rule is always explainable). Pattern-matcher
// rules are not listed here; they come from the compiled YAML catalog.
func RuleMetadata() []rulemeta.Rule {
	var out []rulemeta.Rule
	out = append(out, ci.RuleMetadata()...)
	out = append(out, pkgmeta.RuleMetadata()...)
	out = append(out, jsrisk.RuleMetadata()...)
	out = append(out, pyrisk.RuleMetadata()...)
	out = append(out, rsbuild.RuleMetadata()...)
	out = append(out, pnpmpolicy.RuleMetadata()...)
	out = append(out, agentpolicy.RuleMetadata()...)
	out = append(out, nlp.RuleMetadata()...)
	out = append(out, toxicflow.RuleMetadata()...)
	out = append(out, rugpull.RuleMetadata()...)
	return out
}

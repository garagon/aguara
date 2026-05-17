package packagecheck

import (
	"fmt"

	"github.com/garagon/aguara/internal/intel"
)

// Hit pairs the discovered PackageRef with the intel.Record that
// matched. The CLI converts each Hit into one incident.Finding for
// the flat top-level Findings slice; the per-target FindingsCount
// is computed in Runner.Run before the hits land here.
type Hit struct {
	Ref    PackageRef
	Record intel.Record
}

// RunResult is the output of Runner.Run. Ecosystems is the
// per-target summary surfaced in CheckResult.Ecosystems; Hits is
// the flat hit list (one entry per (ref, matching record) pair)
// the caller converts into Findings.
type RunResult struct {
	Ecosystems []EcosystemResult
	Hits       []Hit
}

// Runner orchestrates per-target parsing + matching. The Matcher
// field is required; callers build it from the intel.Snapshot set
// they want to match against (embedded + optional refreshed
// snapshot via the CLI's --fresh path).
type Runner struct {
	Matcher *intel.Matcher
}

// Run iterates targets, parses each with the per-ecosystem parser,
// looks every PackageRef up in the Matcher, and aggregates the
// results into one RunResult. Empty targets produces an empty
// (non-nil) RunResult so the JSON contract stays `"ecosystems": []`
// instead of `null`.
//
// Errors from a single parse abort the run rather than skipping
// the target. A malformed go.sum is rare enough that surfacing the
// error is more useful than producing a partial result; the caller
// can decide whether to retry or surface the error to the user.
func (r *Runner) Run(targets []Target) (*RunResult, error) {
	out := &RunResult{
		Ecosystems: []EcosystemResult{},
		Hits:       []Hit{},
	}
	if r == nil || r.Matcher == nil {
		return nil, fmt.Errorf("packagecheck: Runner.Matcher is required")
	}
	for _, t := range targets {
		refs, err := parseTarget(t)
		if err != nil {
			return nil, fmt.Errorf("packagecheck: %s: %w", t.Path, err)
		}
		findings := 0
		for _, ref := range refs {
			matches := r.Matcher.MatchPackage(intel.MatchInput{
				Ecosystem: ref.Ecosystem,
				Name:      ref.Name,
				Version:   ref.Version,
				Path:      ref.Path,
			})
			for _, m := range matches {
				out.Hits = append(out.Hits, Hit{Ref: ref, Record: m.Record})
				findings++
			}
		}
		out.Ecosystems = append(out.Ecosystems, EcosystemResult{
			Ecosystem:     t.Ecosystem,
			Path:          t.Path,
			Source:        t.Source,
			PackagesRead:  len(refs),
			FindingsCount: findings,
		})
	}
	return out, nil
}

// parseTarget dispatches by ecosystem to the right parser. Add new
// parsers by extending this switch; Discover already supports
// emitting Targets for ecosystems beyond Go once their parser lands.
func parseTarget(t Target) ([]PackageRef, error) {
	switch t.Ecosystem {
	case intel.EcosystemGo:
		return ParseGo(t)
	default:
		return nil, fmt.Errorf("no parser for ecosystem %q", t.Ecosystem)
	}
}

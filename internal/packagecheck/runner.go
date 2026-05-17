package packagecheck

import (
	"fmt"
	"strings"

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
			// Some ecosystems (Composer especially) routinely
			// ship version strings with a leading `v` while the
			// OSV-side record carries the bare form. We query
			// every alias the per-ecosystem helper returns and
			// dedupe by advisory ID so a single (ref, advisory)
			// match never emits two Findings.
			seen := make(map[string]struct{})
			for _, v := range versionAliases(ref.Ecosystem, ref.Version) {
				matches := r.Matcher.MatchPackage(intel.MatchInput{
					Ecosystem: ref.Ecosystem,
					Name:      ref.Name,
					Version:   v,
					Path:      ref.Path,
				})
				for _, m := range matches {
					if _, dup := seen[m.Record.ID]; dup {
						continue
					}
					seen[m.Record.ID] = struct{}{}
					out.Hits = append(out.Hits, Hit{Ref: ref, Record: m.Record})
					findings++
				}
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
	case intel.EcosystemCargo:
		return ParseCargo(t)
	case intel.EcosystemPackagist:
		return ParseComposer(t)
	case intel.EcosystemRubyGems:
		return ParseRuby(t)
	case intel.EcosystemMaven:
		return ParseMaven(t)
	case intel.EcosystemNuGet:
		return ParseNuGet(t)
	default:
		return nil, fmt.Errorf("no parser for ecosystem %q", t.Ecosystem)
	}
}

// versionAliases returns the version strings the runner should
// query the matcher with for a given (ecosystem, raw version)
// pair. The first entry is always the raw version; per-ecosystem
// conventions add aliases.
//
// Composer is the only ecosystem that needs an alias today:
// composer.lock often ships `v1.2.3` while OSV Packagist records
// publish the bare form `1.2.3`. Stripping the `v` prefix as an
// alias matches either side without requiring the parser to pick
// one canonical form (which would lose information when the
// lockfile literally uses the prefixed form).
//
// Adding a new ecosystem alias rule is one case-arm here; the
// per-ecosystem normalisation in intel/ecosystem.go stays focused
// on name canonicalisation.
func versionAliases(ecosystem, version string) []string {
	out := []string{version}
	if ecosystem == intel.EcosystemPackagist {
		if alias := strings.TrimPrefix(version, "v"); alias != version && alias != "" {
			out = append(out, alias)
		}
	}
	return out
}

package packagecheck

import (
	"fmt"
	"path/filepath"
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
	// AdvisoryIDs lists every distinct advisory ID that matched the
	// selected version, in matcher order; AdvisoryIDs[0] == Record.ID.
	// A tuple covered by both an OSV record and a GHSA alias, for
	// example, keeps both identifiers visible to the caller.
	AdvisoryIDs []string
}

// RunResult is the output of Runner.Run. Ecosystems is the
// per-target summary surfaced in CheckResult.Ecosystems; Hits is
// the flat hit list (one entry per (ref, matching record) pair)
// the caller converts into Findings.
type RunResult struct {
	Ecosystems []EcosystemResult
	Hits       []Hit
	// UnresolvedIncludes lists each requirements include that was not
	// read, once even when several targets reach the same directive.
	UnresolvedIncludes []UnresolvedInclude
	// ReadFiles lists every dependency file the run read, by resolved
	// path (symlinks evaluated), including requirements files reached
	// only through a -r / -c include. A file in this list was
	// evaluated even when discovery did not return it as a target.
	ReadFiles []string
}

// ResolvedPath returns path with its directory's symlinks evaluated, the
// form RunResult.ReadFiles uses, or path unchanged when it cannot be
// resolved.
func ResolvedPath(path string) string {
	dir, err := realDir(filepath.Dir(path))
	if err != nil {
		return filepath.Clean(path)
	}
	return filepath.Join(dir, filepath.Base(path))
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
	// Requirements files can include each other, so one file may be
	// reached from several discovered targets. The cache parses each
	// file once per run, and the seen set reports a PyPI entry (file,
	// line, package) once even when several targets include it. Other
	// ecosystems never share an entry between targets.
	cache := newRequirementsCache()
	seen := map[hitKey]bool{}
	seenInclude := map[hitKey]bool{}
	for _, t := range targets {
		parsed, err := parseTargetDetail(t, cache)
		if err != nil {
			return nil, fmt.Errorf("packagecheck: %s: %w", t.Path, err)
		}
		out.ReadFiles = append(out.ReadFiles, ResolvedPath(t.Path))
		out.ReadFiles = append(out.ReadFiles, parsed.files...)
		refs := parsed.refs
		findings := 0
		unpinned := 0
		// pinnedPyPI holds the PEP 503 names this target pins exactly,
		// in a requirement or a constraint: pip installs that version,
		// which was checked, so a range for the same name elsewhere in
		// the target leaves nothing unchecked.
		pinnedPyPI := map[string]bool{}
		for _, ref := range refs {
			if ref.Ecosystem == intel.EcosystemPyPI && !ref.Unpinned {
				pinnedPyPI[intel.PEP503Normalize(ref.Name)] = true
			}
		}
		for _, ref := range refs {
			// A constraint (from a constraints file or a -c include)
			// installs nothing, so a range there leaves no dependency
			// unchecked: only requirements count as unpinned.
			pinnedElsewhere := ref.Ecosystem == intel.EcosystemPyPI && pinnedPyPI[intel.PEP503Normalize(ref.Name)]
			if ref.Unpinned && ref.Group != constraintGroup && !pinnedElsewhere {
				unpinned++
			}
			// One Hit per (ecosystem, name, version, path) tuple,
			// even when multiple advisories cover the same
			// exposure. Two reasons:
			//
			//   1. Some ecosystems (Composer especially) ship
			//      version strings with a leading `v` while OSV
			//      records carry the bare form, so we have to
			//      query every alias the per-ecosystem helper
			//      returns. The first alias that hits wins; we
			//      do not walk the rest.
			//   2. Once manual intel and OSV both cover a tuple
			//      (e.g. a hand-curated SOCKET-* advisory plus
			//      the upstream MAL-* record after OSV catches
			//      up), the matcher returns both records. The
			//      user is exposed once, not twice; collapsing
			//      to a single Hit keeps the user-facing count
			//      stable across `aguara check` and `aguara
			//      check --fresh`.
			//
			// The matcher itself keeps returning every record so
			// correlation layers (intel.Matcher consumers,
			// future analyzers) can still see the full set; we
			// dedupe here at the output boundary.
			//
			// EmbeddedSnapshots() returns manual first and OSV
			// second, so matches[0] picks the manual advisory
			// ID when both are present.
			//
			// An unpinned ref is looked up with an empty version, which
			// the matcher answers only from all-versions entries: every
			// release of such a package is malicious, so no version has
			// to be guessed.
			var matches []intel.Match
			for _, v := range versionAliases(ref.Ecosystem, ref.Version) {
				matches = r.Matcher.MatchPackage(intel.MatchInput{
					Ecosystem: ref.Ecosystem,
					Name:      ref.Name,
					Version:   v,
					Path:      ref.Path,
				})
				if len(matches) > 0 {
					break
				}
			}
			if len(matches) == 0 {
				continue
			}
			if ref.Ecosystem == intel.EcosystemPyPI {
				key := hitKey{name: ref.Name, version: ref.Version, constraint: ref.Constraint, path: ref.Path, line: ref.Line}
				if seen[key] {
					continue
				}
				seen[key] = true
			}
			out.Hits = append(out.Hits, Hit{Ref: ref, Record: matches[0].Record, AdvisoryIDs: advisoryIDs(matches)})
			findings++
		}
		out.Ecosystems = append(out.Ecosystems, EcosystemResult{
			Ecosystem:          t.Ecosystem,
			Path:               t.Path,
			Source:             t.Source,
			PackagesRead:       len(refs),
			FindingsCount:      findings,
			Unpinned:           unpinned,
			UnresolvedIncludes: len(parsed.unresolved),
		})
		for _, u := range parsed.unresolved {
			key := hitKey{name: u.Argument, path: u.Path, line: u.Line}
			if seenInclude[key] {
				continue
			}
			seenInclude[key] = true
			out.UnresolvedIncludes = append(out.UnresolvedIncludes, u)
		}
	}
	return out, nil
}

// hitKey identifies one reported PyPI entry. Path and Line keep
// distinct files (and distinct lines of one requirements file)
// separate; only the same entry reached twice collapses.
type hitKey struct {
	name, version, constraint, path string
	line                            int
}

func advisoryIDs(matches []intel.Match) []string {
	ids := make([]string, 0, len(matches))
	seen := make(map[string]bool, len(matches))
	for _, m := range matches {
		if m.Record.ID == "" || seen[m.Record.ID] {
			continue
		}
		seen[m.Record.ID] = true
		ids = append(ids, m.Record.ID)
	}
	return ids
}

// parsedTarget is a parser's result plus the bookkeeping the
// EcosystemResult reports beyond the refs themselves.
type parsedTarget struct {
	refs       []PackageRef
	unresolved []UnresolvedInclude
	// files are the requirements files read, by resolved path,
	// including files reached only through an include.
	files []string
}

// parseTargetDetail dispatches like parseTarget but keeps the
// requirements-include bookkeeping and shares the per-run include cache.
func parseTargetDetail(t Target, cache *requirementsCache) (parsedTarget, error) {
	if t.Ecosystem == intel.EcosystemPyPI && isRequirementsSource(t.Source) {
		return parseRequirementsTarget(t, cache)
	}
	refs, err := parseTarget(t)
	return parsedTarget{refs: refs}, err
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
	case intel.EcosystemPyPI:
		// Python dependency files. Installed environments
		// (site-packages) are read by the incident package, not here.
		switch {
		case t.Source == "uv.lock":
			return ParseUVLock(t)
		case t.Source == "poetry.lock":
			return ParsePoetryLock(t)
		case t.Source == "Pipfile.lock":
			return ParsePipfileLock(t)
		case t.Source == "pdm.lock":
			return ParsePDMLock(t)
		case isPylockName(t.Source):
			return ParsePylock(t)
		case isRequirementsSource(t.Source):
			return ParseRequirements(t)
		default:
			return nil, fmt.Errorf("packagecheck: no PyPI parser for source %q", t.Source)
		}
	case intel.EcosystemNPM:
		// npm is unique in that the packagecheck path handles
		// lockfile-style sources only (pnpm-lock.yaml today;
		// package-lock.json / yarn.lock in follow-ups). The
		// installed-tree npm signal (node_modules + .pnpm store)
		// continues to flow through incident.CheckNPM, which
		// produces its own ecosystems[] entry with
		// Source="node_modules". Switching on Source here lets
		// us add new npm lockfile formats without expanding the
		// outer ecosystem switch.
		switch t.Source {
		case "pnpm-lock.yaml":
			return ParsePNPMLock(t)
		case "package-lock.json":
			return ParsePackageLock(t)
		case "yarn.lock":
			return ParseYarnLock(t)
		case "bun.lock":
			return ParseBunLock(t)
		case "bun.lockb":
			return nil, fmt.Errorf("bun.lockb is a binary lockfile and is not supported; commit the text bun.lock instead (bun install writes it by default since Bun 1.2)")
		default:
			return nil, fmt.Errorf("packagecheck: no npm parser for source %q", t.Source)
		}
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

package intel

import "strings"

// EcosystemSpec is the registry entry for a supported ecosystem.
// Aguara consults the registry whenever it needs to:
//
//   - canonicalise a user-provided ecosystem alias to an OSV bucket
//     key (CLI flags, YAML config, library options),
//   - normalise a package name for matcher comparison (PEP 503 for
//     PyPI, lower-case for npm / Packagist / NuGet / RubyGems /
//     crates.io, case-preserving for Go and Maven),
//   - render the supported-choice list a help or error message
//     shows to the user.
//
// The registry is the single source of truth. Older code paths
// (matcher.normalizeEcosystem, intel.canonicaliseEcosystemForUpdate,
// osvimport.canonicaliseEcosystem) now delegate here rather than
// owning their own switch.
type EcosystemSpec struct {
	// ID is the OSV bucket key, byte-for-byte as OSV publishes it.
	// Record.Ecosystem stores this value, and the matcher's index
	// key is built from it. Case matters: OSV serves "PyPI", not
	// "pypi"; "crates.io", not "Crates.io".
	ID string

	// Aliases are alternative spellings users can pass on the CLI
	// or in a YAML config. Lookup is case-insensitive, so "python",
	// "Python", and "PYTHON" all map to PyPI. The canonical ID is
	// always implicitly accepted in addition to the explicit alias
	// list; alias entries that duplicate the ID are tolerated.
	Aliases []string

	// NormalizePackageName turns a raw package name into the form
	// the matcher's index uses. Different ecosystems carry different
	// rules:
	//
	//   - npm / Packagist / RubyGems / NuGet / crates.io: case-fold
	//     because their registries treat names case-insensitively
	//     for matching purposes.
	//   - PyPI: PEP 503 (lower-case + collapse runs of [-_.] into
	//     a single '-').
	//   - Go: case-preserving trim because module paths are
	//     case-sensitive (`github.com/PuerkitoBio/goquery` differs
	//     from `github.com/puerkitobio/goquery` at the proxy).
	//   - Maven: case-preserving trim because groupId:artifactId
	//     is case-sensitive in central.
	//
	// Each spec's function must be pure and safe for concurrent use.
	NormalizePackageName func(name string) string
}

var ecosystemRegistry = []EcosystemSpec{
	{
		ID:                   EcosystemNPM,
		Aliases:              []string{"npm"},
		NormalizePackageName: nameTrimKeepCase,
	},
	{
		ID:      EcosystemPyPI,
		Aliases: []string{"pypi", "python"},
		// PEP 503 normalisation operates on the name proper; the
		// registry trims surrounding whitespace first so callers
		// can hand it a raw token from a lockfile or CLI flag.
		NormalizePackageName: func(s string) string { return PEP503Normalize(strings.TrimSpace(s)) },
	},
	{
		ID:                   EcosystemGo,
		Aliases:              []string{"go", "golang"},
		NormalizePackageName: nameTrimKeepCase,
	},
	{
		ID:                   EcosystemCargo,
		Aliases:              []string{"crates.io", "cargo", "rust"},
		NormalizePackageName: nameLowerTrim,
	},
	{
		ID:                   EcosystemPackagist,
		Aliases:              []string{"packagist", "php", "composer"},
		NormalizePackageName: nameLowerTrim,
	},
	{
		ID:                   EcosystemRubyGems,
		Aliases:              []string{"rubygems", "ruby", "gem"},
		NormalizePackageName: nameLowerTrim,
	},
	{
		ID:                   EcosystemMaven,
		Aliases:              []string{"maven", "java"},
		NormalizePackageName: nameTrimKeepCase,
	},
	{
		ID:                   EcosystemNuGet,
		Aliases:              []string{"nuget", "dotnet", "csharp"},
		NormalizePackageName: nameLowerTrim,
	},
}

func nameLowerTrim(s string) string     { return strings.ToLower(strings.TrimSpace(s)) }
func nameTrimKeepCase(s string) string  { return strings.TrimSpace(s) }

// CanonicaliseEcosystem maps a user-provided ecosystem alias to its
// OSV bucket key. Returns "" when the value is not in the registry,
// so callers can distinguish "unknown ecosystem" from a successful
// match on every alias.
//
// Lookup is case-insensitive over the alias list AND the canonical
// ID. So "PyPI", "pypi", "Python", "python" all resolve to "PyPI";
// "crates.io", "CRATES.IO", "cargo", "rust" all resolve to
// "crates.io".
//
// Whitespace is trimmed so a user copying `--ecosystem ` followed by
// a trailing space does not silently fail.
func CanonicaliseEcosystem(raw string) string {
	key := strings.ToLower(strings.TrimSpace(raw))
	if key == "" {
		return ""
	}
	for _, spec := range ecosystemRegistry {
		if strings.ToLower(spec.ID) == key {
			return spec.ID
		}
		for _, alias := range spec.Aliases {
			if strings.ToLower(alias) == key {
				return spec.ID
			}
		}
	}
	return ""
}

// SupportedEcosystems returns the canonical IDs in registry order
// (npm, PyPI, Go, crates.io, Packagist, RubyGems, Maven, NuGet).
// Callers that need a stable list for help text or test assertions
// should use this rather than spelling the IDs out by hand; adding
// an ecosystem to the registry flows through here automatically.
func SupportedEcosystems() []string {
	out := make([]string, 0, len(ecosystemRegistry))
	for _, s := range ecosystemRegistry {
		out = append(out, s.ID)
	}
	return out
}

// SupportedEcosystemsHint renders the supported-ecosystem list the
// way an error message wants to show it. Each entry is the
// canonical ID; non-trivial aliases trail in parentheses so the
// user discovers them.
//
// Example output:
//
//	npm, PyPI (python), Go (golang), crates.io (cargo, rust), Packagist (php, composer), RubyGems (ruby, gem), Maven (java), NuGet (dotnet, csharp)
//
// The format matches the "supported: ..." pattern existing errors
// already use, so swapping the hardcoded list for this hint does
// not change error-message shape.
func SupportedEcosystemsHint() string {
	parts := make([]string, 0, len(ecosystemRegistry))
	for _, spec := range ecosystemRegistry {
		extras := extraAliases(spec)
		if len(extras) == 0 {
			parts = append(parts, spec.ID)
			continue
		}
		parts = append(parts, spec.ID+" ("+strings.Join(extras, ", ")+")")
	}
	return strings.Join(parts, ", ")
}

// extraAliases returns the alias list with any alias that equals
// (case-insensitively) the canonical ID dropped, so the hint string
// does not say `npm (npm)`.
func extraAliases(spec EcosystemSpec) []string {
	out := make([]string, 0, len(spec.Aliases))
	for _, a := range spec.Aliases {
		if strings.EqualFold(a, spec.ID) {
			continue
		}
		out = append(out, a)
	}
	return out
}

// lookupSpec returns the registry entry for an OSV bucket key.
// Unknown IDs return ok=false so callers can fall back to a safe
// default rather than dereferencing a zero EcosystemSpec.
func lookupSpec(id string) (EcosystemSpec, bool) {
	for _, spec := range ecosystemRegistry {
		if spec.ID == id {
			return spec, true
		}
	}
	return EcosystemSpec{}, false
}

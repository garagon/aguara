package incident

import (
	"testing"

	"github.com/garagon/aguara/internal/intel"
)

// TestEmbeddedSnapshotCoversAllEightEcosystems locks the v0.17
// snapshot regeneration: the binary must ship records for every
// canonical OSV bucket the registry knows. A future regeneration
// that drops an ecosystem (or forgets to re-pass --from-zip /
// --ecosystem for one of them) fails this test loud rather than
// silently shipping a 6-ecosystem snapshot with a 8-ecosystem
// README.
//
// Go is allowed to have zero records (vuln.go.dev is a CVE/range
// stream; PR #100 documented this). What we assert is that the
// SourceMeta block lists every supported ecosystem so the
// regeneration step actually consumed all 8 zips.
func TestEmbeddedSnapshotCoversAllEightEcosystems(t *testing.T) {
	seen := map[string]bool{}
	for _, src := range EmbeddedIntelSnapshot.Sources {
		// SourceMeta.Name is rendered as "osv.dev/<lowercase
		// bucket>" by update-intel; map it back to the canonical
		// bucket for the assertion.
		name := src.Name
		switch name {
		case "osv.dev/npm":
			seen[intel.EcosystemNPM] = true
		case "osv.dev/pypi":
			seen[intel.EcosystemPyPI] = true
		case "osv.dev/go":
			seen[intel.EcosystemGo] = true
		case "osv.dev/crates.io":
			seen[intel.EcosystemCargo] = true
		case "osv.dev/packagist":
			seen[intel.EcosystemPackagist] = true
		case "osv.dev/rubygems":
			seen[intel.EcosystemRubyGems] = true
		case "osv.dev/maven":
			seen[intel.EcosystemMaven] = true
		case "osv.dev/nuget":
			seen[intel.EcosystemNuGet] = true
		}
	}
	for _, want := range intel.SupportedEcosystems() {
		if !seen[want] {
			t.Errorf("embedded snapshot missing source for ecosystem %s (snapshot Sources=%+v)", want, EmbeddedIntelSnapshot.Sources)
		}
	}
}

// TestEmbeddedSnapshotHasRecordsForStrongCoverageEcosystems locks
// the README's "strong embedded malicious-package coverage"
// promise. The two ecosystems classified as strong-coverage in
// v0.17 (npm + PyPI already shipped; RubyGems + NuGet added in
// PR #5) MUST contribute records, or the README claim drifts from
// the binary.
//
// The other four (Go, crates.io, Packagist, Maven) are classified
// "parser ready; range-aware OSV matching deferred" and may have
// zero or few records today. This test does NOT assert on those
// so the parser-ready tier can stay honest.
func TestEmbeddedSnapshotHasRecordsForStrongCoverageEcosystems(t *testing.T) {
	counts := map[string]int{}
	for _, rec := range EmbeddedIntelSnapshot.Records {
		counts[rec.Ecosystem]++
	}
	strong := []string{intel.EcosystemNPM, intel.EcosystemPyPI, intel.EcosystemRubyGems, intel.EcosystemNuGet}
	for _, eco := range strong {
		if counts[eco] == 0 {
			t.Errorf("embedded snapshot has zero records for strong-coverage ecosystem %s (counts=%+v)", eco, counts)
		}
	}
}

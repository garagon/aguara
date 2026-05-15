package intel_test

import (
	"testing"

	"github.com/garagon/aguara/internal/intel"
	"github.com/stretchr/testify/require"
)

// buildMatcher is a small convenience for the table tests below.
func buildMatcher(t *testing.T, records ...intel.Record) *intel.Matcher {
	t.Helper()
	return intel.NewMatcher(intel.Snapshot{
		SchemaVersion: intel.CurrentSchemaVersion,
		Records:       records,
	})
}

func TestMatcherExactNPM(t *testing.T) {
	m := buildMatcher(t,
		intel.Record{
			ID:        "SOCKET-2026-node-ipc",
			Ecosystem: intel.EcosystemNPM,
			Name:      "node-ipc",
			Kind:      intel.KindCompromised,
			Versions:  []string{"12.0.1"},
		},
	)

	hit := m.MatchPackage(intel.MatchInput{
		Ecosystem: intel.EcosystemNPM,
		Name:      "node-ipc",
		Version:   "12.0.1",
	})
	require.Len(t, hit, 1)
	require.Equal(t, "SOCKET-2026-node-ipc", hit[0].Record.ID)

	miss := m.MatchPackage(intel.MatchInput{
		Ecosystem: intel.EcosystemNPM,
		Name:      "node-ipc",
		Version:   "12.0.0",
	})
	require.Empty(t, miss, "exact-version matcher must not generalise to neighbours")
}

func TestMatcherNormalizesPyPI(t *testing.T) {
	// PEP 503: `Foo_Bar` and `foo-bar` must collide. The advisory
	// has the canonical form; the looked-up name has the wild
	// form, and they must match.
	m := buildMatcher(t,
		intel.Record{
			ID:        "OSV-PYPI-foo-bar",
			Ecosystem: intel.EcosystemPyPI,
			Name:      "foo-bar",
			Kind:      intel.KindMalicious,
			Versions:  []string{"1.0.0"},
		},
	)

	for _, name := range []string{"foo-bar", "Foo_Bar", "foo.bar", "FOO__BAR", "foo--bar"} {
		hit := m.MatchPackage(intel.MatchInput{
			Ecosystem: intel.EcosystemPyPI,
			Name:      name,
			Version:   "1.0.0",
		})
		require.Lenf(t, hit, 1, "PyPI normalisation must accept %q", name)
	}
}

func TestMatcherDoesNotCrossEcosystems(t *testing.T) {
	// An npm advisory for "rc" must never match a PyPI package
	// called "rc". This is the regression behaviour
	// IsCompromisedIn already enforces; new matcher must keep it.
	m := buildMatcher(t,
		intel.Record{
			ID:        "OSV-NPM-rc",
			Ecosystem: intel.EcosystemNPM,
			Name:      "rc",
			Kind:      intel.KindCompromised,
			Versions:  []string{"1.2.9"},
		},
	)

	miss := m.MatchPackage(intel.MatchInput{
		Ecosystem: intel.EcosystemPyPI,
		Name:      "rc",
		Version:   "1.2.9",
	})
	require.Empty(t, miss)
}

func TestMatcherIgnoresWithdrawn(t *testing.T) {
	// Withdrawn records must be excluded at index time so they
	// never appear in MatchPackage output -- even though the
	// (name, version) tuple matches.
	m := buildMatcher(t,
		intel.Record{
			ID:        "OSV-PYPI-withdrawn",
			Ecosystem: intel.EcosystemPyPI,
			Name:      "ghost",
			Kind:      intel.KindMalicious,
			Versions:  []string{"1.0.0"},
			Withdrawn: true,
		},
	)
	hit := m.MatchPackage(intel.MatchInput{
		Ecosystem: intel.EcosystemPyPI,
		Name:      "ghost",
		Version:   "1.0.0",
	})
	require.Empty(t, hit)
}

func TestMatcherEcosystemAliases(t *testing.T) {
	// The matcher's ecosystem normalisation accepts "python" as
	// an alias for "PyPI" because the check command uses python
	// internally. A lookup keyed by either spelling must hit a
	// record stored under either spelling.
	m := buildMatcher(t,
		intel.Record{
			ID:        "OSV-PYPI-aliased",
			Ecosystem: "python",
			Name:      "litellm",
			Versions:  []string{"1.82.7"},
		},
	)
	for _, eco := range []string{"PyPI", "pypi", "python", "Python"} {
		hit := m.MatchPackage(intel.MatchInput{
			Ecosystem: eco,
			Name:      "litellm",
			Version:   "1.82.7",
		})
		require.Lenf(t, hit, 1, "ecosystem alias %q must resolve", eco)
	}
}

func TestMatcherPreservesMatchInputPath(t *testing.T) {
	// Match.Path comes from the MatchInput; the matcher must
	// thread it through unchanged so callers can surface the
	// on-disk location of a compromised package without storing
	// it themselves.
	m := buildMatcher(t,
		intel.Record{
			ID:        "OSV-NPM-foo",
			Ecosystem: intel.EcosystemNPM,
			Name:      "@scope/foo",
			Versions:  []string{"2.0.0"},
		},
	)
	hit := m.MatchPackage(intel.MatchInput{
		Ecosystem: intel.EcosystemNPM,
		Name:      "@scope/foo",
		Version:   "2.0.0",
		Path:      "/path/to/node_modules/@scope/foo",
	})
	require.Len(t, hit, 1)
	require.Equal(t, "/path/to/node_modules/@scope/foo", hit[0].Path)
}

func TestMatcherPreservesNPMScopeCase(t *testing.T) {
	// npm names are case-sensitive AND scope is part of the
	// identity. `@AWS/sdk` and `@aws/sdk` are different packages
	// in the registry, so the matcher must NOT lower-case them.
	m := buildMatcher(t,
		intel.Record{
			ID:        "OSV-NPM-scoped",
			Ecosystem: intel.EcosystemNPM,
			Name:      "@aws/sdk",
			Versions:  []string{"3.0.0"},
		},
	)
	require.Len(t,
		m.MatchPackage(intel.MatchInput{Ecosystem: "npm", Name: "@aws/sdk", Version: "3.0.0"}),
		1,
	)
	require.Empty(t,
		m.MatchPackage(intel.MatchInput{Ecosystem: "npm", Name: "@AWS/sdk", Version: "3.0.0"}),
		"npm matcher must not collapse case across scopes",
	)
}

func TestMatcherNilSafeOnEmptySnapshot(t *testing.T) {
	// An empty/zero-value Matcher must return nil on any input,
	// not panic. Callers that always run with the embedded
	// snapshot are still safe even before that snapshot is
	// initialised.
	var m *intel.Matcher
	require.Nil(t, m.MatchPackage(intel.MatchInput{
		Ecosystem: intel.EcosystemNPM,
		Name:      "anything",
		Version:   "1.0.0",
	}))

	m = intel.NewMatcher()
	require.Nil(t, m.MatchPackage(intel.MatchInput{
		Ecosystem: intel.EcosystemNPM,
		Name:      "anything",
		Version:   "1.0.0",
	}))
}

func TestMatcherDedupAcrossSnapshots(t *testing.T) {
	// A record with the same (ecosystem, name, ID) coming from
	// two snapshots (the documented manual + OSV case) must only
	// produce one Match. Without this, every compromised package
	// found via two sources would show up as two findings in the
	// terminal output.
	rec := intel.Record{
		ID:        "DUP-1",
		Ecosystem: intel.EcosystemNPM,
		Name:      "node-ipc",
		Versions:  []string{"12.0.1"},
	}
	m := intel.NewMatcher(
		intel.Snapshot{Records: []intel.Record{rec}},
		intel.Snapshot{Records: []intel.Record{rec}},
	)
	hits := m.MatchPackage(intel.MatchInput{
		Ecosystem: "npm",
		Name:      "node-ipc",
		Version:   "12.0.1",
	})
	require.Len(t, hits, 1, "duplicate records across snapshots must collapse to a single Match")
	require.Equal(t, "DUP-1", hits[0].Record.ID)
}

func TestMatcherDistinctIDsAtSameTupleStaySeparate(t *testing.T) {
	// Two records that share (ecosystem, name, version) but carry
	// different advisory IDs are distinct intel entries (e.g. an
	// OSV advisory PLUS a Socket advisory for the same compromise).
	// The matcher must surface both so consumers can correlate.
	m := intel.NewMatcher(
		intel.Snapshot{Records: []intel.Record{{
			ID:        "OSV-1",
			Ecosystem: intel.EcosystemNPM,
			Name:      "node-ipc",
			Versions:  []string{"12.0.1"},
		}}},
		intel.Snapshot{Records: []intel.Record{{
			ID:        "SOCKET-1",
			Ecosystem: intel.EcosystemNPM,
			Name:      "node-ipc",
			Versions:  []string{"12.0.1"},
		}}},
	)
	hits := m.MatchPackage(intel.MatchInput{
		Ecosystem: "npm",
		Name:      "node-ipc",
		Version:   "12.0.1",
	})
	require.Len(t, hits, 2, "distinct advisory IDs at the same tuple must not collapse")
	seen := map[string]bool{}
	for _, h := range hits {
		seen[h.Record.ID] = true
	}
	require.True(t, seen["OSV-1"])
	require.True(t, seen["SOCKET-1"])
}

func TestMatcherPEP503TrailingSeparator(t *testing.T) {
	// A pathological PyPI name ending in `.` or `_` must normalise
	// cleanly without leaving a trailing separator that would
	// cause a name mismatch.
	require.Equal(t, "foo", intel.PEP503Normalize("foo."))
	require.Equal(t, "foo", intel.PEP503Normalize("foo_"))
	require.Equal(t, "foo-bar", intel.PEP503Normalize("foo..bar"))
	require.Equal(t, "foo-bar", intel.PEP503Normalize("foo__bar"))
}

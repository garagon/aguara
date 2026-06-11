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

func TestMatcherWithdrawnTombstonesEarlierLiveRecord(t *testing.T) {
	// Codex P2 regression (PR 2 review, round 4): a refreshed
	// snapshot that marks an advisory as Withdrawn must override
	// any earlier non-withdrawn copy with the same (ecosystem,
	// name, ID). Without this, an advisory the upstream source
	// has retracted keeps producing matches indefinitely after
	// the user runs `aguara update`.
	live := intel.Record{
		ID:        "ADV-RETRACT",
		Ecosystem: intel.EcosystemNPM,
		Name:      "ghost-pkg",
		Kind:      intel.KindCompromised,
		Versions:  []string{"1.0.0"},
	}
	retracted := live
	retracted.Withdrawn = true

	// Live first, withdrawn second (the realistic refresh order):
	m := intel.NewMatcher(
		intel.Snapshot{Records: []intel.Record{live}},
		intel.Snapshot{Records: []intel.Record{retracted}},
	)
	hits := m.MatchPackage(intel.MatchInput{
		Ecosystem: "npm",
		Name:      "ghost-pkg",
		Version:   "1.0.0",
	})
	require.Empty(t, hits, "later withdrawn record must tombstone earlier live copy")

	// Reverse order also tombstones -- order-independence is
	// part of the contract so callers do not have to reason
	// about snapshot load order.
	m = intel.NewMatcher(
		intel.Snapshot{Records: []intel.Record{retracted}},
		intel.Snapshot{Records: []intel.Record{live}},
	)
	hits = m.MatchPackage(intel.MatchInput{
		Ecosystem: "npm",
		Name:      "ghost-pkg",
		Version:   "1.0.0",
	})
	require.Empty(t, hits, "withdrawn before live must still tombstone")
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

func TestMatcherMergesVersionsAcrossSnapshots(t *testing.T) {
	// Codex P2 regression (PR 2 review): when the same advisory ID
	// appears in two snapshots with DIFFERENT version coverage --
	// the realistic "manual ships old versions, OSV refresh adds a
	// fresh one" case -- the matcher must union the version lists.
	// Dropping the later record entirely would silently miss a
	// compromised version the user just refreshed intel for.
	manual := intel.Record{
		ID:        "ADV-1",
		Ecosystem: intel.EcosystemNPM,
		Name:      "node-ipc",
		Kind:      intel.KindCompromised,
		Summary:   "manual: original advisory text",
		Versions:  []string{"12.0.1"},
	}
	osv := intel.Record{
		ID:        "ADV-1",
		Ecosystem: intel.EcosystemNPM,
		Name:      "node-ipc",
		Kind:      intel.KindCompromised,
		Summary:   "OSV: refreshed advisory text (should NOT override)",
		Versions:  []string{"12.0.2"},
	}
	m := intel.NewMatcher(
		intel.Snapshot{Records: []intel.Record{manual}},
		intel.Snapshot{Records: []intel.Record{osv}},
	)
	// Looking up the manual-only version hits.
	hits := m.MatchPackage(intel.MatchInput{Ecosystem: "npm", Name: "node-ipc", Version: "12.0.1"})
	require.Len(t, hits, 1)
	// Looking up the OSV-only version also hits -- this is the
	// regression: without the merge, the second snapshot was
	// dropped and 12.0.2 reported as clean.
	hits = m.MatchPackage(intel.MatchInput{Ecosystem: "npm", Name: "node-ipc", Version: "12.0.2"})
	require.Len(t, hits, 1, "version-only-in-second-snapshot must surface via merge")
	// And the first-occurrence metadata wins, because manual
	// advisories must keep their display priority.
	require.Contains(t, hits[0].Record.Summary, "manual")
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

// --- range matching (PR 2) ---

func TestMatcherRangeOnlyNPMWholePackage(t *testing.T) {
	// The TrapDoor shape: a malicious npm record with no exact
	// versions, only an introduced:0 open range. Every installed
	// version must match.
	m := buildMatcher(t, intel.Record{
		ID:        "MAL-2026-4275",
		Ecosystem: intel.EcosystemNPM,
		Name:      "async-pipeline-builder",
		Kind:      intel.KindMalicious,
		Ranges:    []intel.VersionRange{{Type: "SEMVER", Introduced: "0"}},
	})
	for _, v := range []string{"1.0.12", "0.0.1", "9.9.9"} {
		hit := m.MatchPackage(intel.MatchInput{Ecosystem: intel.EcosystemNPM, Name: "async-pipeline-builder", Version: v})
		require.Len(t, hit, 1, "version %s should match introduced:0 whole-package range", v)
		require.Equal(t, "MAL-2026-4275", hit[0].Record.ID)
	}
}

func TestMatcherRangeFixedBoundaryExclusive(t *testing.T) {
	m := buildMatcher(t, intel.Record{
		ID:        "MAL-RANGE",
		Ecosystem: intel.EcosystemNPM,
		Name:      "pkg",
		Kind:      intel.KindMalicious,
		Ranges:    []intel.VersionRange{{Type: "SEMVER", Introduced: "1.0.0", Fixed: "1.0.13"}},
	})
	require.Len(t, m.MatchPackage(intel.MatchInput{Ecosystem: intel.EcosystemNPM, Name: "pkg", Version: "1.0.12"}), 1)
	require.Empty(t, m.MatchPackage(intel.MatchInput{Ecosystem: intel.EcosystemNPM, Name: "pkg", Version: "1.0.13"}), "fixed is exclusive")
	require.Empty(t, m.MatchPackage(intel.MatchInput{Ecosystem: intel.EcosystemNPM, Name: "pkg", Version: "0.9.9"}), "below introduced")
}

func TestMatcherExactAndRangeSameRecordNoDuplicate(t *testing.T) {
	// A record carrying both an exact Version and an overlapping
	// Range must produce exactly one Match for a version that
	// satisfies both: exact takes priority and the record is not
	// double-counted.
	m := buildMatcher(t, intel.Record{
		ID:        "MAL-BOTH",
		Ecosystem: intel.EcosystemNPM,
		Name:      "pkg",
		Kind:      intel.KindMalicious,
		Versions:  []string{"1.0.12"},
		Ranges:    []intel.VersionRange{{Type: "SEMVER", Introduced: "0"}},
	})
	require.Len(t, m.MatchPackage(intel.MatchInput{Ecosystem: intel.EcosystemNPM, Name: "pkg", Version: "1.0.12"}), 1,
		"exact+range on one record must yield one match, not two")
	require.Len(t, m.MatchPackage(intel.MatchInput{Ecosystem: intel.EcosystemNPM, Name: "pkg", Version: "2.0.0"}), 1,
		"range-only hit on the same record still yields one match")
}

func TestMatcherRangeIgnoredForUnsupportedEcosystem(t *testing.T) {
	// PyPI is not a semver range ecosystem in phase 1; a PyPI
	// range-only record must not match (PEP 440 support is future).
	m := buildMatcher(t, intel.Record{
		ID:        "OSV-PYPI-RANGE",
		Ecosystem: intel.EcosystemPyPI,
		Name:      "somepkg",
		Kind:      intel.KindMalicious,
		Ranges:    []intel.VersionRange{{Type: "ECOSYSTEM", Introduced: "0"}},
	})
	require.Empty(t, m.MatchPackage(intel.MatchInput{Ecosystem: intel.EcosystemPyPI, Name: "somepkg", Version: "0.1.0"}),
		"PyPI range-only must not match until PEP 440 support lands")
}

func TestMatcherRangeUnsupportedTypeNoMatch(t *testing.T) {
	m := buildMatcher(t, intel.Record{
		ID:        "MAL-GIT",
		Ecosystem: intel.EcosystemNPM,
		Name:      "pkg",
		Kind:      intel.KindMalicious,
		Ranges:    []intel.VersionRange{{Type: "GIT", Introduced: "0"}},
	})
	require.Empty(t, m.MatchPackage(intel.MatchInput{Ecosystem: intel.EcosystemNPM, Name: "pkg", Version: "1.0.0"}),
		"a non-semver range type must not be evaluated")
}

func TestMatcherMergesRangesAcrossSnapshots(t *testing.T) {
	// Same advisory ID in two snapshots, each carrying a different
	// range. The merged record must match versions covered by either.
	snap1 := intel.Snapshot{SchemaVersion: intel.CurrentSchemaVersion, Records: []intel.Record{{
		ID: "MAL-MERGE", Ecosystem: intel.EcosystemNPM, Name: "pkg", Kind: intel.KindMalicious,
		Ranges: []intel.VersionRange{{Type: "SEMVER", Introduced: "1.0.0", Fixed: "2.0.0"}},
	}}}
	snap2 := intel.Snapshot{SchemaVersion: intel.CurrentSchemaVersion, Records: []intel.Record{{
		ID: "MAL-MERGE", Ecosystem: intel.EcosystemNPM, Name: "pkg", Kind: intel.KindMalicious,
		Ranges: []intel.VersionRange{{Type: "SEMVER", Introduced: "3.0.0", Fixed: "4.0.0"}},
	}}}
	m := intel.NewMatcher(snap1, snap2)
	require.Len(t, m.MatchPackage(intel.MatchInput{Ecosystem: intel.EcosystemNPM, Name: "pkg", Version: "1.5.0"}), 1, "first range")
	require.Len(t, m.MatchPackage(intel.MatchInput{Ecosystem: intel.EcosystemNPM, Name: "pkg", Version: "3.5.0"}), 1, "second range (merged)")
	require.Empty(t, m.MatchPackage(intel.MatchInput{Ecosystem: intel.EcosystemNPM, Name: "pkg", Version: "2.5.0"}), "gap between merged ranges")
}

func TestMatcherWithdrawnTombstoneRetractsRangeRecord(t *testing.T) {
	live := intel.Snapshot{SchemaVersion: intel.CurrentSchemaVersion, Records: []intel.Record{{
		ID: "MAL-RETRACT", Ecosystem: intel.EcosystemNPM, Name: "pkg", Kind: intel.KindMalicious,
		Ranges: []intel.VersionRange{{Type: "SEMVER", Introduced: "0"}},
	}}}
	tomb := intel.Snapshot{SchemaVersion: intel.CurrentSchemaVersion, Records: []intel.Record{{
		ID: "MAL-RETRACT", Ecosystem: intel.EcosystemNPM, Name: "pkg", Withdrawn: true,
	}}}
	m := intel.NewMatcher(live, tomb)
	require.Empty(t, m.MatchPackage(intel.MatchInput{Ecosystem: intel.EcosystemNPM, Name: "pkg", Version: "1.0.0"}),
		"a withdrawn tombstone must retract the live range record")
}

func TestMatcherDistinctIDsExactAndRangeBothMatch(t *testing.T) {
	// Manual exact advisory + OSV range advisory for the same npm
	// tuple, distinct IDs. Both surface at the matcher layer
	// (provenance); the output layer collapses them to one finding.
	// Manual snapshot loads first, so it keeps display priority.
	manual := intel.Snapshot{SchemaVersion: intel.CurrentSchemaVersion, Records: []intel.Record{{
		ID: "SOCKET-2026-05-24-trapdoor", Ecosystem: intel.EcosystemNPM, Name: "dev-env-bootstrapper",
		Kind: intel.KindCompromised, Versions: []string{"1.0.12"},
	}}}
	osv := intel.Snapshot{SchemaVersion: intel.CurrentSchemaVersion, Records: []intel.Record{{
		ID: "MAL-2026-4277", Ecosystem: intel.EcosystemNPM, Name: "dev-env-bootstrapper",
		Kind: intel.KindMalicious, Ranges: []intel.VersionRange{{Type: "SEMVER", Introduced: "0"}},
	}}}
	m := intel.NewMatcher(manual, osv)
	hit := m.MatchPackage(intel.MatchInput{Ecosystem: intel.EcosystemNPM, Name: "dev-env-bootstrapper", Version: "1.0.12"})
	require.Len(t, hit, 2, "distinct IDs (manual exact + OSV range) both surface at the matcher layer")
	require.Equal(t, "SOCKET-2026-05-24-trapdoor", hit[0].Record.ID, "manual advisory keeps first/display priority")
}

// ---------------------------------------------------------------------------
// All-versions entries (C3-A)

func TestMatcher_AllVersionsEntryMatchesAnyVersion(t *testing.T) {
	snap := intel.Snapshot{AllVersions: []intel.AllVersionsEntry{
		{ID: "MAL-2026-0001", Ecosystem: intel.EcosystemNPM, Name: "evil-pkg"},
	}}
	m := intel.NewMatcher(snap)
	for _, v := range []string{"0.0.1", "9.9.9", "1.0.0-beta.1", "not-even-semver"} {
		got := m.MatchPackage(intel.MatchInput{Ecosystem: "npm", Name: "evil-pkg", Version: v})
		if len(got) != 1 {
			t.Fatalf("version %q: want 1 match, got %d", v, len(got))
		}
		rec := got[0].Record
		if rec.ID != "MAL-2026-0001" || rec.Kind != intel.KindMalicious {
			t.Errorf("unexpected record: %+v", rec)
		}
		if rec.Summary == "" || len(rec.References) == 0 {
			t.Errorf("synthesized record must carry summary and reference: %+v", rec)
		}
	}
	// Different package stays silent.
	if got := m.MatchPackage(intel.MatchInput{Ecosystem: "npm", Name: "good-pkg", Version: "1.0.0"}); len(got) != 0 {
		t.Errorf("unrelated package matched: %v", got)
	}
}

func TestMatcher_AllVersionsTombstoned(t *testing.T) {
	live := intel.Snapshot{AllVersions: []intel.AllVersionsEntry{
		{ID: "MAL-X", Ecosystem: intel.EcosystemNPM, Name: "pkg"},
	}}
	retract := intel.Snapshot{Records: []intel.Record{
		{ID: "MAL-X", Ecosystem: intel.EcosystemNPM, Name: "pkg", Withdrawn: true},
	}}
	m := intel.NewMatcher(live, retract)
	if got := m.MatchPackage(intel.MatchInput{Ecosystem: "npm", Name: "pkg", Version: "1.0.0"}); len(got) != 0 {
		t.Errorf("tombstoned all-versions entry still matched: %v", got)
	}
}

func TestMatcher_AllVersionsDedupesAgainstRecordWithSameID(t *testing.T) {
	snap := intel.Snapshot{
		Records: []intel.Record{
			{ID: "MAL-X", Ecosystem: intel.EcosystemNPM, Name: "pkg", Kind: intel.KindMalicious, Versions: []string{"1.0.0"}},
		},
		AllVersions: []intel.AllVersionsEntry{
			{ID: "MAL-X", Ecosystem: intel.EcosystemNPM, Name: "pkg"},
		},
	}
	m := intel.NewMatcher(snap)
	// Exact version hit: the record matches; the entry must not add a
	// second finding for the same advisory.
	got := m.MatchPackage(intel.MatchInput{Ecosystem: "npm", Name: "pkg", Version: "1.0.0"})
	if len(got) != 1 {
		t.Fatalf("want 1 match, got %d", len(got))
	}
	// Non-listed version: the record misses, the entry covers it.
	got = m.MatchPackage(intel.MatchInput{Ecosystem: "npm", Name: "pkg", Version: "2.0.0"})
	if len(got) != 1 {
		t.Fatalf("want 1 entry match for unlisted version, got %d", len(got))
	}
}

func TestMatcher_AllVersionsKeepsDistinctIDs(t *testing.T) {
	// Mirrors the Records contract: distinct advisory IDs for the same
	// package are useful provenance and all surface, manual-first;
	// exact duplicates collapse.
	manual := intel.Snapshot{AllVersions: []intel.AllVersionsEntry{
		{ID: "MANUAL-1", Ecosystem: intel.EcosystemNPM, Name: "pkg"},
	}}
	osv := intel.Snapshot{AllVersions: []intel.AllVersionsEntry{
		{ID: "MAL-2", Ecosystem: intel.EcosystemNPM, Name: "pkg"},
		{ID: "MANUAL-1", Ecosystem: intel.EcosystemNPM, Name: "pkg"}, // duplicate: collapsed
	}}
	m := intel.NewMatcher(manual, osv)
	got := m.MatchPackage(intel.MatchInput{Ecosystem: "npm", Name: "pkg", Version: "1.0.0"})
	if len(got) != 2 || got[0].Record.ID != "MANUAL-1" || got[1].Record.ID != "MAL-2" {
		t.Fatalf("want [MANUAL-1, MAL-2], got %v", got)
	}
}

func TestSnapshot_AllVersionsRoundTrip(t *testing.T) {
	snap := intel.Snapshot{
		SchemaVersion: intel.CurrentSchemaVersion,
		AllVersions: []intel.AllVersionsEntry{
			{ID: "MAL-1", Ecosystem: intel.EcosystemNPM, Name: "a"},
			{ID: "MAL-2", Ecosystem: "pypi", Name: "b"},
		},
	}
	gz, err := intel.EncodeSnapshotGZIP(snap)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	back, err := intel.DecodeSnapshotGZIP(gz)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(back.AllVersions) != 2 || back.AllVersions[0] != snap.AllVersions[0] {
		t.Fatalf("round trip lost entries: %+v", back.AllVersions)
	}
}

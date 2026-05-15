package incident_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/incident"
	"github.com/garagon/aguara/internal/intel"
	"github.com/stretchr/testify/require"
)

// TestKnownCompromisedSnapshotParity asserts that every legacy
// IsCompromisedIn hit is also a hit through the intel.Matcher built
// from KnownCompromisedSnapshot(). This is the load-bearing
// migration check: as long as parity holds, we can ship the
// snapshot adapter without breaking any caller that still uses
// IsCompromised / IsCompromisedIn.
func TestKnownCompromisedSnapshotParity(t *testing.T) {
	snap := incident.KnownCompromisedSnapshot()
	require.NotEmpty(t, snap.Records, "snapshot must mirror the manual list")

	m := intel.NewMatcher(snap)

	for _, cp := range incident.KnownCompromised {
		eco := cp.Ecosystem
		if eco == "" {
			eco = incident.EcosystemPyPI
		}
		for _, v := range cp.Versions {
			legacy := incident.IsCompromisedIn(eco, cp.Name, v)
			require.NotNilf(t, legacy, "legacy must hit %s %s@%s", eco, cp.Name, v)

			hits := m.MatchPackage(intel.MatchInput{
				Ecosystem: eco,
				Name:      cp.Name,
				Version:   v,
			})
			require.NotEmptyf(t, hits,
				"matcher must hit %s %s@%s (parity with legacy lookup)", eco, cp.Name, v)

			// At least one record must carry the same advisory
			// id so consumers correlating advisories between the
			// two paths get a stable identifier.
			var matched bool
			for _, h := range hits {
				if h.Record.ID == cp.Advisory {
					matched = true
					break
				}
			}
			require.Truef(t, matched,
				"matcher hit for %s %s@%s does not carry advisory %s", eco, cp.Name, v, cp.Advisory)
		}
	}
}

func TestKnownCompromisedSnapshotShape(t *testing.T) {
	snap := incident.KnownCompromisedSnapshot()
	require.Equal(t, intel.CurrentSchemaVersion, snap.SchemaVersion)
	require.False(t, snap.GeneratedAt.IsZero(), "manual snapshot must carry a deterministic timestamp")
	require.NotEmpty(t, snap.Sources)
	for _, src := range snap.Sources {
		require.Equal(t, intel.SourceManual, src.Kind)
	}
}

func TestKnownCompromisedSnapshotReproducible(t *testing.T) {
	// Two calls back-to-back must produce identical snapshots so
	// the embedded summary stays stable across `aguara check`
	// invocations within the same binary. Catches accidental
	// time.Now() / global state leaking into the adapter.
	a := incident.KnownCompromisedSnapshot()
	b := incident.KnownCompromisedSnapshot()
	require.Equal(t, a.GeneratedAt, b.GeneratedAt)
	require.Equal(t, len(a.Records), len(b.Records))
	for i := range a.Records {
		require.Equal(t, a.Records[i].ID, b.Records[i].ID)
		require.Equal(t, a.Records[i].Versions, b.Records[i].Versions)
	}
}

func TestCheckResultIntelSummaryPopulated(t *testing.T) {
	// Both check entry points must populate IntelSummary on every
	// run. Build a real node_modules fixture so CheckNPM reaches
	// the result-construction path; without this the codex P3
	// regression fires -- a missing path returns early and the
	// test never asserts the IntelSummary fields it's there to
	// protect.
	nm := filepath.Join(t.TempDir(), "node_modules")
	require.NoError(t, os.MkdirAll(filepath.Join(nm, "lodash"), 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(nm, "lodash", "package.json"),
		[]byte(`{"name":"lodash","version":"4.17.21"}`),
		0o644,
	))

	result, err := incident.CheckNPM(incident.CheckOptions{Path: nm})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "offline", result.Intel.Mode)
	require.Equal(t, "embedded", result.Intel.Snapshot)
	require.False(t, result.Intel.GeneratedAt.IsZero(),
		"IntelSummary.GeneratedAt must be set from the embedded snapshot")
	require.NotEmpty(t, result.Intel.Sources)
	for _, src := range result.Intel.Sources {
		require.Truef(t, strings.EqualFold(src, "manual"),
			"embedded snapshot must carry only manual source, got %q", src)
	}
}

func TestCheckResultIntelSummaryPopulatedForPython(t *testing.T) {
	// Parity assertion for the Python check entry point. We give
	// Check a path that is a real (empty) directory so it does not
	// error out, then assert the same Intel fields.
	siteDir := t.TempDir()
	result, err := incident.Check(incident.CheckOptions{Path: siteDir})
	require.NoError(t, err)
	require.Equal(t, "offline", result.Intel.Mode)
	require.Equal(t, "embedded", result.Intel.Snapshot)
	require.False(t, result.Intel.GeneratedAt.IsZero())
	require.NotEmpty(t, result.Intel.Sources)
}

func TestKnownCompromisedSnapshotKindCompromised(t *testing.T) {
	// Codex P2 regression: every entry in KnownCompromised is a
	// legitimate package whose specific versions were hijacked,
	// not a malicious typosquat. The summary text often mentions
	// "malicious payload" / "malicious dependency"; that must not
	// flip the record to KindMalicious because consumers use
	// RecordKind for remediation messaging ("remove forever" vs
	// "pin to a fixed version").
	snap := incident.KnownCompromisedSnapshot()
	for _, rec := range snap.Records {
		require.Equalf(t, intel.KindCompromised, rec.Kind,
			"manual entry %q (%s) must be KindCompromised, got %q",
			rec.ID, rec.Name, rec.Kind)
	}
}

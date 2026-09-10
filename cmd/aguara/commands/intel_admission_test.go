package commands

import (
	"testing"

	"github.com/garagon/aguara/internal/incident"
	"github.com/garagon/aguara/internal/intel"
	"github.com/stretchr/testify/require"
)

func TestLocalVerifiedLegacyIntelCannotRestoreRejectedClassification(t *testing.T) {
	s := &intel.Store{Dir: t.TempDir()}
	legacy := intel.Snapshot{SchemaVersion: intel.CurrentSchemaVersion, Records: []intel.Record{
		{ID: "GHSA-generic", Ecosystem: "PyPI", Name: "pip", Kind: intel.KindMalicious, Versions: []string{"25.1"}},
		{ID: "GHSA-pjxp-f379-6284", Ecosystem: "npm", Name: "@fangrong/xoc", Kind: intel.KindMalicious, Versions: []string{"1.0.5", "1.0.6"}},
	}}
	require.NoError(t, s.SaveVerified(legacy))
	ov := localOrEmbeddedOverride(s)
	require.NotNil(t, ov)
	last := ov.Snapshots[len(ov.Snapshots)-1]
	require.Len(t, last.Records, 1)
	require.Equal(t, []string{"1.0.6"}, last.Records[0].Versions)
	m := incident.MatcherForOverride(ov)
	require.Empty(t, m.MatchPackage(intel.MatchInput{Ecosystem: "PyPI", Name: "pip", Version: "25.1"}))
	require.Empty(t, m.MatchPackage(intel.MatchInput{Ecosystem: "npm", Name: "@fangrong/xoc", Version: "1.0.5"}))
	require.NotEmpty(t, m.MatchPackage(intel.MatchInput{Ecosystem: "npm", Name: "@fangrong/xoc", Version: "1.0.6"}))
	// The reader does not rewrite authenticated cache bytes or its marker.
	stored, err := s.LoadVerified()
	require.NoError(t, err)
	require.Equal(t, legacy, *stored)
}

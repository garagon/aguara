package intel_test

import (
	"testing"

	"github.com/garagon/aguara/internal/intel"
	"github.com/stretchr/testify/require"
)

func TestOSVAdmissionMigratesLegacyWithoutMutatingInput(t *testing.T) {
	s := intel.Snapshot{Sources: []intel.SourceMeta{{Kind: intel.SourceOSV}, {Kind: intel.SourceManual}}, Records: []intel.Record{
		{ID: "GHSA-generic", Name: "pip", Ecosystem: "PyPI", Versions: []string{"25.1"}},
		{ID: "MAL-2026-1", Name: "bad", Ecosystem: "npm", Versions: []string{"1.0.0"}},
		{ID: "GHSA-pjxp-f379-6284", Name: "@fangrong/xoc", Ecosystem: "npm", Versions: []string{"1.0.5", "1.0.6"}, Ranges: []intel.VersionRange{{Introduced: "0"}}},
		{ID: "GHSA-withdrawn", Name: "old", Ecosystem: "npm", Withdrawn: true},
	}, AllVersions: []intel.AllVersionsEntry{
		{ID: "MAL-2026-2", Name: "all-bad", Ecosystem: "npm"},
		{ID: "GHSA-unproven", Name: "other", Ecosystem: "npm"},
	}}
	for _, revision := range []int{0, 999} {
		s.AdmissionPolicy = revision
		got := intel.ApplyOSVAdmissionPolicy(s)
		require.Equal(t, intel.CurrentOSVAdmissionPolicy, got.AdmissionPolicy)
		require.Len(t, got.Records, 3)
		require.Equal(t, "MAL-2026-1", got.Records[0].ID)
		require.Equal(t, []string{"1.0.6"}, got.Records[1].Versions)
		require.Empty(t, got.Records[1].Ranges)
		require.True(t, got.Records[2].Withdrawn)
		require.Len(t, got.AllVersions, 1)
		require.Equal(t, got, intel.ApplyOSVAdmissionPolicy(got))
	}
	require.Len(t, s.Records, 4)
	require.Equal(t, []string{"1.0.5", "1.0.6"}, s.Records[2].Versions)
	require.Len(t, s.Records[2].Ranges, 1)
	require.Len(t, s.AllVersions, 2)
}

func TestOSVAdmissionReviewedTupleDoesNotAuthorizeAnotherTarget(t *testing.T) {
	for _, pair := range [][2]string{{"PyPI", "@fangrong/xoc"}, {"npm", "other"}} {
		require.Empty(t, intel.ReviewedOSVVersions("GHSA-pjxp-f379-6284", pair[0], pair[1], []string{"1.0.6"}))
	}
	require.Empty(t, intel.ReviewedOSVVersions("GHSA-unknown", "npm", "@fangrong/xoc", []string{"1.0.6"}))
	require.Empty(t, intel.ReviewedOSVVersions("GHSA-pjxp-f379-6284", "npm", "@fangrong/xoc", []string{"1.0.5", "9.0.0"}))
}

func TestOSVAdmissionCurrentPolicyPreservesProducerCoverage(t *testing.T) {
	s := intel.Snapshot{AdmissionPolicy: intel.CurrentOSVAdmissionPolicy, Records: []intel.Record{{ID: "GHSA-reviewed-source", Name: "new-package", Ecosystem: "npm", Versions: []string{"1.0.0"}}}}
	require.Equal(t, s, intel.ApplyOSVAdmissionPolicy(s))
}

func TestOSVAdmissionRejectsContradictedGuardrailsVersions(t *testing.T) {
	s := intel.Snapshot{Records: []intel.Record{
		{ID: "PYSEC-2026-206", Name: "guardrails-ai", Ecosystem: "PyPI", Versions: []string{"0.1.0", "0.10.0"}},
		{ID: "GHSA-xmpw-2vmm-p4p6", Name: "guardrails-ai", Ecosystem: "PyPI", Versions: []string{"0.10.0", "0.10.1", "0.10.2"}},
	}}
	got := intel.ApplyOSVAdmissionPolicy(s)
	require.Len(t, got.Records, 1)
	require.Equal(t, "GHSA-xmpw-2vmm-p4p6", got.Records[0].ID)
	require.Equal(t, []string{"0.10.1"}, got.Records[0].Versions)
}

package incident

import (
	"testing"

	"github.com/garagon/aguara/internal/intel"
	"github.com/stretchr/testify/require"
)

func TestEmbeddedAdmissionExcludesVulnerableButNotMaliciousPackages(t *testing.T) {
	m := defaultIntelMatcher()
	for _, target := range []intel.MatchInput{
		{Ecosystem: "PyPI", Name: "ansible", Version: "2.8.0"},
		{Ecosystem: "PyPI", Name: "dbt-core", Version: "1.6.0"},
		{Ecosystem: "PyPI", Name: "guardrails-ai", Version: "0.10.0"},
		{Ecosystem: "PyPI", Name: "guardrails-ai", Version: "0.10.2"},
		{Ecosystem: "Maven", Name: "org.apache.dubbo:dubbo", Version: "3.1.0"},
		{Ecosystem: "npm", Name: "@fangrong/xoc", Version: "1.0.5"},
	} {
		require.Empty(t, m.MatchPackage(target), "%s@%s", target.Name, target.Version)
	}
	for _, target := range []intel.MatchInput{
		{Ecosystem: "PyPI", Name: "guardrails-ai", Version: "0.10.1"},
		{Ecosystem: "npm", Name: "@fangrong/xoc", Version: "1.0.6"},
		{Ecosystem: "npm", Name: "flatmap-stream", Version: "0.1.1"},
		{Ecosystem: "npm", Name: "nx", Version: "21.5.0"},
	} {
		require.NotEmpty(t, m.MatchPackage(target), "%s@%s", target.Name, target.Version)
	}
	idx := buildPyPIFilenameIndex(EmbeddedSnapshots())
	require.NotContains(t, idx, "ansible")
	require.NotContains(t, idx, "dbt-core")
	require.Contains(t, idx, "guardrails-ai")
}

func TestEmbeddedAdmissionPreservesManualAndMALCoverage(t *testing.T) {
	raw, err := intel.DecodeSnapshotGZIP(generatedIntelGZ)
	require.NoError(t, err)
	filtered := EmbeddedIntelSnapshot()
	require.Less(t, len(filtered.Records), len(raw.Records))
	require.Equal(t, raw.AllVersions, filtered.AllVersions)
	require.Equal(t, KnownCompromisedSnapshot(), EmbeddedSnapshots()[0])
	t.Logf("embedded records: %d -> %d; all-versions: %d unchanged", len(raw.Records), len(filtered.Records), len(filtered.AllVersions))
}

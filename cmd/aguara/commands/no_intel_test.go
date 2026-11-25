package commands

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/garagon/aguara/internal/packagecheck"
)

const podfileLock = "PODS:\n  - Alamofire (5.8.1)\n\nCOCOAPODS: 1.15.2\n"

// A lockfile of an ecosystem with no Aguara intelligence is not
// unevaluated because of its format: the messages say Aguara has no
// package intelligence for it, and triage still asks for review.
func TestNoIntelEcosystemLockfileIsDescribedAsSuch(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := projectWith(t, map[string]string{"ios/Podfile.lock": podfileLock})

	result := auditToFile(t, dir)
	require.Equal(t, "review", result.Triage.Decision)
	require.False(t, result.Plan.CanInstallDependencies)
	requireTriageReason(t, result.Triage, "dependency_evidence_not_evaluated")
	for _, r := range result.Triage.Reasons {
		if r.Kind == "dependency_evidence_not_evaluated" {
			require.Contains(t, r.Message, "ios/Podfile.lock (Aguara has no package intelligence for CocoaPods)")
			require.NotContains(t, r.Message, "parse")
		}
	}

	out := readReport(t, "audit", dir)
	require.Contains(t, out, "Not evaluated: ios/Podfile.lock (Aguara has no package intelligence for CocoaPods; no packages in it were checked)")
	require.Contains(t, out, "No packages were checked: Aguara has no package intelligence for the ecosystems of the dependency files found.")
	require.NotContains(t, out, "cannot parse")
}

// Mixed files get one line per cause.
func TestUnsupportedEvidenceLinesSplitByCause(t *testing.T) {
	c := &packagecheck.Coverage{UnsupportedEvidence: []packagecheck.UnsupportedEvidence{
		{Path: "/repo/deno.lock", Kind: "deno.lock", Ecosystem: "npm"},
		{Path: "/repo/app/pubspec.lock", Kind: "pubspec.lock", Ecosystem: "Pub"},
		{Path: "/repo/ios/Podfile.lock", Kind: "Podfile.lock", Ecosystem: "CocoaPods"},
	}}
	require.Equal(t, []string{
		"Not evaluated: deno.lock (dependency file Aguara cannot parse; no packages in it were checked)",
		"Not evaluated: app/pubspec.lock, ios/Podfile.lock (Aguara has no package intelligence for Pub, CocoaPods; no packages in them were checked)",
	}, unsupportedEvidenceLines(c, "/repo"))
}

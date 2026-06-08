package aguara_test

import (
	"context"
	"testing"

	"github.com/garagon/aguara"
)

// TestScanContentPnpmPolicy verifies the pnpm-policy analyzer is wired
// into the public ScanContent path: a pnpm-workspace.yaml that disables
// build approval surfaces PNPM_DANGEROUS_BUILDS_001 through the Go API.
func TestScanContentPnpmPolicy(t *testing.T) {
	result, err := aguara.ScanContent(
		context.Background(),
		"dangerouslyAllowAllBuilds: true\nminimumReleaseAge: 0\n",
		"pnpm-workspace.yaml",
	)
	if err != nil {
		t.Fatalf("ScanContent failed: %v", err)
	}
	want := map[string]bool{
		"PNPM_DANGEROUS_BUILDS_001":         false,
		"PNPM_MIN_RELEASE_AGE_DISABLED_001": false,
	}
	for _, f := range result.Findings {
		if _, ok := want[f.RuleID]; ok {
			want[f.RuleID] = true
		}
	}
	for id, seen := range want {
		if !seen {
			t.Errorf("expected %s in ScanContent findings", id)
		}
	}
}

// TestScanContentPnpmPolicyNoFalsePositive confirms a hardened
// pnpm-workspace.yaml emits no pnpm-policy findings through the API.
func TestScanContentPnpmPolicyNoFalsePositive(t *testing.T) {
	result, err := aguara.ScanContent(
		context.Background(),
		"minimumReleaseAge: 1440\nstrictDepBuilds: true\nblockExoticSubdeps: true\n",
		"pnpm-workspace.yaml",
	)
	if err != nil {
		t.Fatalf("ScanContent failed: %v", err)
	}
	for _, f := range result.Findings {
		if f.Analyzer == "pnpm-policy" {
			t.Errorf("unexpected pnpm-policy finding on hardened config: %s", f.RuleID)
		}
	}
}

package aguara_test

import (
	"context"
	"testing"

	"github.com/garagon/aguara"
)

func TestScanContentPNPMPolicyAliases(t *testing.T) {
	for _, tc := range []struct {
		source string
		want   bool
	}{
		{"choice: &enabled true\ndangerouslyAllowAllBuilds: *enabled\n", true},
		{"choice: &true false\ndangerouslyAllowAllBuilds: *true\n", false},
	} {
		r, err := aguara.ScanContent(context.Background(), tc.source, "pnpm-workspace.yaml")
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, f := range r.Findings {
			if f.RuleID == "PNPM_DANGEROUS_BUILDS_001" {
				found = true
				if f.Line != 2 || f.Analyzer != "pnpm-policy" {
					t.Fatalf("unexpected attribution: %+v", f)
				}
			}
		}
		if found != tc.want {
			t.Fatalf("dangerous builds finding = %v, want %v", found, tc.want)
		}
	}
}

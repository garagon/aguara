package aguara_test

import (
	"context"
	"strings"
	"testing"

	"github.com/garagon/aguara"
)

func TestScanContentUnicodeContainsEvidence(t *testing.T) {
	content := strings.Repeat("\u023a", 64) + "\n/var/run/docker.sock"
	result, err := aguara.ScanContent(context.Background(), content, "input.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range result.Findings {
		if finding.RuleID == "SSRF_005" {
			if finding.Line != 2 || finding.MatchedText != "/var/run/docker.sock" {
				t.Fatalf("incorrect evidence: %#v", finding)
			}
			return
		}
	}
	t.Fatal("missing SSRF_005 finding after Unicode prefix")
}

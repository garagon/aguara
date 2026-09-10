package aguara_test

import (
	"context"
	"strings"
	"testing"

	"github.com/garagon/aguara"
)

func TestScanContentExactNPMKeys(t *testing.T) {
	sc, err := aguara.NewScanner()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		src  string
		want bool
	}{
		{"{\n\"scripts\":{\"preinstall\":\"node index.js\"},\n\"Scripts\":null\n}", true},
		{`{"Scripts":{"preinstall":"node index.js"}}`, false},
		{`{"scripts":{"preinstall":"node index.js"},"SCRIPTS":false}`, true},
		{"{\"scripts\":{\"preinstall\":\"node index.js\"},\"\uff53cripts\":null}", true},
		{`{"scripts":{"preinstall":"node index.js"},"\uff53cripts":null}`, true},
	} {
		for _, scan := range []func(context.Context, string, string) (*aguara.ScanResult, error){
			func(ctx context.Context, src, name string) (*aguara.ScanResult, error) {
				return aguara.ScanContent(ctx, src, name)
			},
			func(ctx context.Context, src, name string) (*aguara.ScanResult, error) {
				return sc.ScanContent(ctx, src, name)
			},
			func(ctx context.Context, src, name string) (*aguara.ScanResult, error) {
				return aguara.ScanContentAs(ctx, src, name, "")
			},
			func(ctx context.Context, src, name string) (*aguara.ScanResult, error) {
				return sc.ScanContentAs(ctx, src, name, "")
			},
		} {
			r, err := scan(context.Background(), tc.src, "package.json")
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, f := range r.Findings {
				if f.RuleID == "SUPPLY_026" {
					found = true
					if f.Analyzer != "pkgmeta" || !strings.Contains(f.MatchedText, "node index.js") {
						t.Fatalf("lost evidence: %+v", f)
					}
				}
			}
			if found != tc.want {
				t.Fatalf("SUPPLY_026 = %v, want %v on %s", found, tc.want, tc.src)
			}
		}
	}
}

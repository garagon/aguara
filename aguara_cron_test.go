package aguara_test

import (
	"context"
	"testing"

	"github.com/garagon/aguara"
)

func TestCronWritePublicAPI(t *testing.T) {
	const payload = "# header\nopen('/etc/cron.d/agent', 'w').write('@reboot root /opt/agent\\n')\n"
	s, err := aguara.NewScanner(aguara.WithWorkers(1))
	if err != nil {
		t.Fatal(err)
	}
	for _, scan := range []struct {
		name string
		fn   func(context.Context, string, string) (*aguara.ScanResult, error)
	}{
		{"package", func(ctx context.Context, content, name string) (*aguara.ScanResult, error) {
			return aguara.ScanContent(ctx, content, name)
		}},
		{"reusable", s.ScanContent},
	} {
		t.Run(scan.name, func(t *testing.T) {
			result, err := scan.fn(context.Background(), payload, "install.py")
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for _, f := range result.Findings {
				if f.RuleID != "SC-EX-007" {
					continue
				}
				count++
				if f.Severity != aguara.SeverityCritical || f.Category != "supply-chain-exfil" || f.Analyzer != "script-risk" || f.Line != 2 {
					t.Errorf("persistence contract changed: %+v", f)
				}
			}
			if count != 1 {
				t.Errorf("expected one persistence finding, got %d", count)
			}
			benign, err := scan.fn(context.Background(), "print('hello')", "install.py")
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range benign.Findings {
				if f.RuleID == "SC-EX-007" {
					t.Fatal("scan state leaked across requests")
				}
			}
		})
	}
	disabled, err := aguara.ScanContent(context.Background(), payload, "install.py", aguara.WithDisabledRules("SC-EX-007"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range disabled.Findings {
		if f.RuleID == "SC-EX-007" {
			t.Fatal("disabled rule still emitted")
		}
	}
}

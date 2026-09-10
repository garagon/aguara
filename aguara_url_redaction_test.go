package aguara_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/garagon/aguara"
	"github.com/garagon/aguara/internal/output"
)

func TestScanContentURLUserinfoRedaction(t *testing.T) {
	sc, err := aguara.NewScanner()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, content, rule string }{
		{"setup.sh", "pip install --index-url http://opaqueTOKEN@packages.example/simple x", "SHELL_UNSAFE_PIP_SOURCE_001"},
		{"setup.sh", "npm install --registry http://user:part@opaqueTOKEN@packages.example x", "SHELL_UNSAFE_NPM_SOURCE_001"},
		{"setup.sh", "systemctl --user enable cache.service && pip install --index-url http://opaqueTOKEN@packages.example/simple x", "SC-EX-007"},
		{"package.json", `{"scripts":{"postinstall":"node hook.js"},"dependencies":{"x":"git+https://user:part@opaqueTOKEN@github.com/org/repo.git"}}`, "NPM_LIFECYCLE_GIT_001"},
		{"package.json", `{"optionalDependencies":{"x":"git+https://user:part@opaqueTOKEN@github.com/org/repo.git"}}`, "NPM_OPTIONAL_GIT_001"},
		{"package.json", `{"dependencies":{"x":"git+https://user:part@opaqueTOKEN@github.com/org/repo.git"}}`, "NPM_GIT_INSTALL_TRUST_001"},
		{"package.json", `{"dependencies":{"x":"https://user:part@opaqueTOKEN@packages.example/x.tgz"}}`, "NPM_REMOTE_INSTALL_TRUST_001"},
		{"package.json", `{"optionalDependencies":{"x":"git+https://user:opaque'TOKEN@github.com/org/repo.git"}}`, "NPM_OPTIONAL_GIT_001"},
		{"package.json", "{\n\"scripts\":{\"postinstall\":\"bash setup.sh\"},\n\"dependencies\":{\"x\":\"git+https:\\/\\/opaqueTOKEN@github.com/org/repo.git\"}\n}", "SUPPLY_001"},
		{"package.json", "{\n\"scripts\":{\"postinstall\":\"bash setup.sh\"},\n\"dependencies\":{\"x\":\"git+https://opaqueTOKEN\\u0040github.com/org/repo.git\"}\n}", "SUPPLY_001"},
	} {
		t.Run(tc.rule, func(t *testing.T) {
			r, err := aguara.ScanContent(context.Background(), tc.content, tc.name)
			if err != nil {
				t.Fatal(err)
			}
			hit := false
			for _, f := range r.Findings {
				if f.RuleID == tc.rule {
					hit = true
				}
			}
			if !hit {
				t.Fatalf("missing %s: %+v", tc.rule, r.Findings)
			}
			b, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(b), "TOKEN") {
				t.Fatalf("credential leaked: %s", b)
			}
			var sarif bytes.Buffer
			if err := (&output.SARIFFormatter{}).Format(&sarif, r); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(sarif.String(), "TOKEN") {
				t.Fatal("credential leaked in SARIF")
			}
			reused, err := sc.ScanContent(context.Background(), tc.content, tc.name)
			if err != nil {
				t.Fatal(err)
			}
			b, err = json.Marshal(reused)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(b), "TOKEN") {
				t.Fatal("credential leaked through reusable scanner")
			}
		})
	}
}

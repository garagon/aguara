package rules

import (
	"testing"
)

// Custom rule files arrive via --rules from arbitrary directories, so
// the YAML loader and the rule compiler both face untrusted input.
// Parse errors and compile errors are fine; panics are not.
func FuzzParseAndCompile(f *testing.F) {
	f.Add("- id: T1\n  name: Test\n  severity: high\n  category: test\n  remediation: fix\n  patterns:\n    - type: contains\n      value: bad\n")
	f.Add("- id: T2\n  name: X\n  severity: low\n  category: c\n  remediation: r\n  match_mode: all\n  patterns:\n    - type: regex\n      value: '(?i)a{1,'\n")
	f.Add("---\n- id: A\n---\n- id: B\n")
	f.Add("- &a\n  id: *a\n")

	f.Fuzz(func(t *testing.T, src string) {
		raw, err := parseMultiDocYAML([]byte(src))
		if err != nil {
			return
		}
		for _, r := range raw {
			if _, err := Compile(r); err != nil {
				continue
			}
		}
	})
}

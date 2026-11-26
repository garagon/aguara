package schematest

import (
	"strings"
	"testing"
)

// The helpers must detect what they exist to detect: an undocumented field
// and a type error in a real report shape.
func TestUndocumentedAndValidateDetectDrift(t *testing.T) {
	schema := Load(t, "../../schema/scan-report.schema.json")
	expanded := LoadExpanded(t, "../../schema/scan-report.schema.json")
	doc := []byte(`{"schema_version":"1.0","tool":{"name":"aguara","version":"dev"},
		"catalog":{"detections":1,"pattern_rules":1,"analyzer_rules":0,"digest":"sha256:` + zeros64 + `"},
		"findings":[{"rule_id":"R","rule_name":"n","severity":3,"severity_label":"HIGH","category":"c",
			"file_path":"a.md","line":1,"matched_text":"x","analyzer":"pattern","surprise":true}],
		"files_scanned":1,"rules_loaded":1,"verdict":2,"verdict_label":"block","risk_score":25,"duration_ms":1,
		"brand_new":1}`)
	Validate(t, schema, doc)
	got := Undocumented(t, expanded, doc)
	want := []string{"$.brand_new", "$.findings[].surprise"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("Undocumented = %v, want %v", got, want)
	}

	bad := &fakeT{TB: t}
	Validate(bad, schema, []byte(`{"schema_version":"1.0","tool":{"name":"aguara","version":"dev"},
		"catalog":{"detections":1,"pattern_rules":1,"analyzer_rules":0,"digest":"sha256:`+zeros64+`"},
		"findings":[],"files_scanned":1,"rules_loaded":1,"verdict":"block","verdict_label":"block","risk_score":25,"duration_ms":1}`))
	if !bad.failed {
		t.Fatal("a string verdict must fail validation")
	}
}

// Lazy reference resolution still reaches definitions several levels down
// in the SARIF schema, and rejects the null arrays older releases wrote.
func TestValidateResolvesNestedSARIFReferences(t *testing.T) {
	sarif := Load(t, "../output/testdata/sarif-schema-2.1.0.json")
	run := func(region, rules string) []byte {
		return []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"aguara","rules":` + rules + `}},
			"results":[{"message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.md"},"region":` + region + `}}]}]}]}`)
	}
	Validate(t, sarif, run(`{"startLine":3}`, `[]`))
	spaced := []byte(strings.Replace(string(run(`{"startLine":3}`, `[]`)), `"a.md"`, `"my skill.md"`, 1))
	for _, bad := range [][]byte{run(`{"startLine":0}`, `[]`), run(`{"startLine":3}`, `null`), run(`{"startLine":3,"bogus":1}`, `[]`), spaced} {
		f := &fakeT{TB: t}
		Validate(f, sarif, bad)
		if !f.failed {
			t.Fatalf("invalid SARIF accepted: %s", bad)
		}
	}
}

const zeros64 = "0000000000000000000000000000000000000000000000000000000000000000"

// fakeT records a failure instead of stopping the test, so the test can
// assert that validation fails.
type fakeT struct {
	testing.TB
	failed bool
}

func (f *fakeT) Helper()               {}
func (f *fakeT) Fatalf(string, ...any) { f.failed = true }

func TestIsURIReference(t *testing.T) {
	for _, ok := range []string{"a.md", "skills/my%20skill/SKILL.md", "caf%C3%A9.md", "-dash.md", "100%25.md", "", "https://x.example/a?b#c"} {
		if !IsURIReference(ok) {
			t.Errorf("%q should be a URI reference", ok)
		}
	}
	for _, bad := range []string{"my skill.md", "100%.md", "caf\u00e9.md", "a\\b.md", "x%2", "a\"b"} {
		if IsURIReference(bad) {
			t.Errorf("%q should not be a URI reference", bad)
		}
	}
}

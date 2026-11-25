package schematest

import (
	"testing"
)

// The helpers must detect what they exist to detect: an undocumented field
// and a type error in a real report shape.
func TestUndocumentedAndValidateDetectDrift(t *testing.T) {
	schema := Load(t, "../../schema/scan-report.schema.json")
	doc := []byte(`{"schema_version":"1.0","tool":{"name":"aguara","version":"dev"},
		"catalog":{"detections":1,"pattern_rules":1,"analyzer_rules":0,"digest":"sha256:` + zeros64 + `"},
		"findings":[{"rule_id":"R","rule_name":"n","severity":3,"severity_label":"HIGH","category":"c",
			"file_path":"a.md","line":1,"matched_text":"x","analyzer":"pattern","surprise":true}],
		"files_scanned":1,"rules_loaded":1,"verdict":2,"verdict_label":"block","risk_score":25,"duration_ms":1,
		"brand_new":1}`)
	Validate(t, schema, doc)
	got := Undocumented(t, schema, doc)
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

const zeros64 = "0000000000000000000000000000000000000000000000000000000000000000"

// fakeT records a failure instead of stopping the test, so the test can
// assert that validation fails.
type fakeT struct {
	testing.TB
	failed bool
}

func (f *fakeT) Helper()               {}
func (f *fakeT) Fatalf(string, ...any) { f.failed = true }

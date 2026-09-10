package types

import "testing"

func TestSanitizeURLUserinfo(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"http://TOKEN@host/x", "http://[REDACTED]@host/x"},
		{"HTTPS://user:part@TAIL@[::1]:80/@scope/x", "HTTPS://[REDACTED]@[::1]:80/@scope/x"},
		{"git+custom://user%40TOKEN@host/repo", "git+custom://[REDACTED]@host/repo"},
		{"http://bad%ZZ@host/x", "http://[REDACTED]@host/x"},
		{"http://:@host", "http://[REDACTED]@host"},
		{"http://host/@scope/x?email=a@b#c@d", "http://host/@scope/x?email=a@b#c@d"},
		{"http://host?email=a@b", "http://host?email=a@b"},
		{"http://host#email=a@b", "http://host#email=a@b"},
		{"'http://ONE@host/x' \"https://TWO@other/y\"", "'http://[REDACTED]@host/x' \"https://[REDACTED]@other/y\""},
		{"github:org/repo#ref", "github:org/repo#ref"},
	} {
		got := SanitizeURLUserinfo(tc.in, RedactedPlaceholder+"@")
		if got != tc.want {
			t.Errorf("%q: got %q want %q", tc.in, got, tc.want)
		}
		if again := SanitizeURLUserinfo(got, RedactedPlaceholder+"@"); again != got {
			t.Errorf("not idempotent: %q", again)
		}
	}
}

func TestRedactURLUserinfoAcrossFindingFields(t *testing.T) {
	url := "http://TOKEN@host/simple"
	fs := []Finding{{Description: url, MatchedText: url, Context: []ContextLine{{Content: url}}}}
	RedactSensitiveFindings(fs)
	want := "http://[REDACTED]@host/simple"
	if fs[0].Description != want || fs[0].MatchedText != want || fs[0].Context[0].Content != want {
		t.Fatalf("leaked URL: %+v", fs)
	}
}

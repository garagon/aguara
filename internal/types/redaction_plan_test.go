package types

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRedactionPlanPrivateKeyRanges(t *testing.T) {
	for _, tc := range []struct {
		name, content string
		secretLine    int
		want          bool
	}{
		{"complete", "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----", 2, true},
		{"crlf", "-----BEGIN RSA PRIVATE KEY-----\r\nsecret\r\n-----END RSA PRIVATE KEY-----", 2, true},
		{"truncated", "-----BEGIN EC PRIVATE KEY-----\nsecret\nmore", 3, true},
		{"mismatched end", "-----BEGIN EC PRIVATE KEY-----\n-----END RSA PRIVATE KEY-----\nsecret", 3, true},
		{"tabs", "-----BEGIN\tRSA\tPRIVATE KEY-----\nsecret\n-----END RSA PRIVATE KEY-----", 2, true},
		{"multiline header", "-----BEGIN\nRSA PRIVATE KEY-----\nsecret\n-----END RSA PRIVATE KEY-----", 3, true},
		{"same line next block", "-----BEGIN PRIVATE KEY-----x-----END PRIVATE KEY----------BEGIN EC PRIVATE KEY-----\nsecret\n-----END EC PRIVATE KEY-----", 2, true},
		{"second block", "-----BEGIN PRIVATE KEY-----x-----END PRIVATE KEY-----\nplain\n-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----", 4, true},
		{"between blocks", "-----BEGIN PRIVATE KEY-----x-----END PRIVATE KEY-----\nplain\n-----BEGIN PRIVATE KEY-----x-----END PRIVATE KEY-----", 2, false},
		{"public key", "-----BEGIN PUBLIC KEY-----\npublic\n-----END PUBLIC KEY-----", 2, false},
		{"certificate", "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----", 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var p RedactionPlan
			p.AddContent("key.txt", tc.content)
			lines := strings.Split(tc.content, "\n")
			findings := []Finding{{FilePath: "key.txt", Line: tc.secretLine, MatchedText: lines[tc.secretLine-1], Context: []ContextLine{{Line: tc.secretLine, Content: lines[tc.secretLine-1]}}}}
			p.Apply(findings)
			if got := findings[0].Sensitive; got != tc.want {
				t.Fatalf("sensitive=%v, want %v", got, tc.want)
			}
			if tc.want && (findings[0].MatchedText != RedactedPlaceholder || findings[0].Context[0].Content != RedactedPlaceholder) {
				t.Fatal("private material escaped")
			}
			if !tc.want && findings[0].MatchedText != lines[tc.secretLine-1] {
				t.Fatal("public material changed")
			}
		})
	}
}

func TestRedactionPlanPreservesLegacyContextAndPrivateMetadata(t *testing.T) {
	f := Finding{Category: "credential-leak", FilePath: "a.txt", Line: 2, MatchedText: "secret", Context: []ContextLine{{Line: 1, Content: "keep"}, {Line: 2, Content: "secret", IsMatch: true}}}
	f.AddEvidenceRange(2, 2)
	var p RedactionPlan
	p.AddFindings([]Finding{f})
	findings := []Finding{f}
	p.Apply(findings)
	if findings[0].MatchedText != RedactedPlaceholder || findings[0].Context[0].Content != "keep" {
		t.Fatal("legacy credential context contract changed")
	}
	data, err := json.Marshal(findings)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "evidenceRanges") || strings.Contains(string(data), "evidence_ranges") {
		t.Fatal("internal source ranges entered JSON")
	}
}

func TestRedactionPlanRetainsFilteredLocations(t *testing.T) {
	var p RedactionPlan
	p.AddFindings([]Finding{{FilePath: "a.txt", Line: 2, Category: "credential-leak", Context: []ContextLine{{Line: 1, Content: "keep"}, {Line: 2, Content: "secret", IsMatch: true}}}})
	findings := []Finding{
		{FilePath: "a.txt", Line: 3, MatchedText: "danger", Context: []ContextLine{{Line: 1, Content: "keep"}, {Line: 2, Content: "secret"}}},
		{FilePath: "b.txt", Line: 3, Context: []ContextLine{{Line: 2, Content: "keep"}}},
	}
	p.Apply(findings)
	if findings[0].Context[1].Content != RedactedPlaceholder {
		t.Fatal("filtered secret escaped")
	}
	if findings[0].Context[0].Content != "keep" || findings[1].Context[0].Content != "keep" || findings[0].MatchedText != "danger" {
		t.Fatal("unrelated evidence changed")
	}
}

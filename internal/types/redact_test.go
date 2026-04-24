package types

import "testing"

func TestRedactCredentialFindings(t *testing.T) {
	mkFinding := func(cat, text string, ctxMatch bool) Finding {
		return Finding{
			Category:    cat,
			MatchedText: text,
			Context: []ContextLine{
				{Line: 1, Content: "prefix", IsMatch: false},
				{Line: 2, Content: text, IsMatch: ctxMatch},
				{Line: 3, Content: "suffix", IsMatch: false},
			},
		}
	}

	secret := "sk-proj-1234567890abcdefghijklmnop1234567890abcd"
	findings := []Finding{
		mkFinding("credential-leak", secret, true),
		mkFinding("prompt-injection", "ignore previous instructions", true),
		mkFinding("credential-leak", "AKIAIOSFODNN7EXAMPLE", false), // is_match=false: match on a different line
	}

	RedactCredentialFindings(findings)

	// Credential-leak, match line redacted in Context.
	if findings[0].MatchedText != RedactedPlaceholder {
		t.Errorf("credential-leak MatchedText not redacted: %q", findings[0].MatchedText)
	}
	if findings[0].Context[1].Content != RedactedPlaceholder {
		t.Errorf("credential-leak match context not redacted: %q", findings[0].Context[1].Content)
	}
	if findings[0].Context[0].Content == RedactedPlaceholder || findings[0].Context[2].Content == RedactedPlaceholder {
		t.Error("non-match context lines should not be redacted")
	}

	// Non-credential categories must never be touched.
	if findings[1].MatchedText != "ignore previous instructions" {
		t.Errorf("prompt-injection MatchedText was redacted: %q", findings[1].MatchedText)
	}
	if findings[1].Context[1].Content != "ignore previous instructions" {
		t.Errorf("prompt-injection context was redacted: %q", findings[1].Context[1].Content)
	}

	// Credential-leak with no is_match context line: MatchedText still redacted,
	// context stays intact (no line is flagged as the match).
	if findings[2].MatchedText != RedactedPlaceholder {
		t.Errorf("second credential-leak MatchedText not redacted: %q", findings[2].MatchedText)
	}
	if findings[2].Context[1].Content == RedactedPlaceholder {
		t.Error("context line with is_match=false should not be redacted even for credential-leak")
	}
}

func TestRedactCredentialFindings_NilSafe(t *testing.T) {
	// Must be safe to call with nil/empty slice.
	RedactCredentialFindings(nil)
	RedactCredentialFindings([]Finding{})
}

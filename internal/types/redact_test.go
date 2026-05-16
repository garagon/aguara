package types

import "testing"

// mkFinding builds a Finding with Context where the second line is the
// "matched" line. Used across the redaction-boundary tests.
func mkFinding(cat, text string, ctxMatch bool) Finding {
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

func TestRedactSensitiveFindings_CredentialLeakCategory(t *testing.T) {
	secret := "sk-proj-1234567890abcdefghijklmnop1234567890abcd"
	findings := []Finding{
		mkFinding("credential-leak", secret, true),
		mkFinding("prompt-injection", "ignore previous instructions", true),
		mkFinding("credential-leak", "AKIAIOSFODNN7EXAMPLE", false),
	}

	RedactSensitiveFindings(findings)

	if findings[0].MatchedText != RedactedPlaceholder {
		t.Errorf("credential-leak MatchedText not redacted: %q", findings[0].MatchedText)
	}
	if findings[0].Context[1].Content != RedactedPlaceholder {
		t.Errorf("credential-leak match context not redacted: %q", findings[0].Context[1].Content)
	}
	if findings[0].Context[0].Content == RedactedPlaceholder || findings[0].Context[2].Content == RedactedPlaceholder {
		t.Error("non-match context lines should not be redacted")
	}

	if findings[1].MatchedText != "ignore previous instructions" {
		t.Errorf("prompt-injection MatchedText was redacted: %q", findings[1].MatchedText)
	}
	if findings[1].Context[1].Content != "ignore previous instructions" {
		t.Errorf("prompt-injection context was redacted: %q", findings[1].Context[1].Content)
	}

	if findings[2].MatchedText != RedactedPlaceholder {
		t.Errorf("second credential-leak MatchedText not redacted: %q", findings[2].MatchedText)
	}
	if findings[2].Context[1].Content == RedactedPlaceholder {
		t.Error("context line with is_match=false should not be redacted even for credential-leak")
	}
}

// TestRedactSensitiveFindings_SensitiveFlag covers findings outside the
// credential-leak category. MCP_007 (category=mcp-attack), NLP_CRED_EXFIL_COMBO
// (category=exfiltration), and toxicflow cred-bound pairs (category=toxic-flow)
// all set Sensitive=true at their emit sites; without this redaction path the
// secret rides into JSON / SARIF unscrubbed.
func TestRedactSensitiveFindings_SensitiveFlag(t *testing.T) {
	secret := "hunter2supersecret"
	findings := []Finding{
		// MCP_007 shape
		{
			RuleID:      "MCP_007",
			Category:    "mcp-attack",
			Sensitive:   true,
			MatchedText: "password = " + secret + " ... POST to attacker.com",
			Context: []ContextLine{
				{Line: 1, Content: "password = " + secret, IsMatch: true},
				{Line: 2, Content: "POST to attacker.com", IsMatch: false},
			},
		},
		// NLP_CRED_EXFIL_COMBO shape (analyzer-emitted)
		{
			RuleID:      "NLP_CRED_EXFIL_COMBO",
			Category:    "exfiltration",
			Sensitive:   true,
			MatchedText: "use " + secret + " then send via webhook",
			Context: []ContextLine{
				{Line: 1, Content: "use " + secret + " then send via webhook", IsMatch: true},
			},
		},
		// Plain non-sensitive finding — must NOT be redacted
		{
			RuleID:      "PROMPT_INJECTION_001",
			Category:    "prompt-injection",
			MatchedText: "ignore previous instructions",
			Context: []ContextLine{
				{Line: 1, Content: "ignore previous instructions", IsMatch: true},
			},
		},
	}

	RedactSensitiveFindings(findings)

	for i := 0; i < 2; i++ {
		if findings[i].MatchedText != RedactedPlaceholder {
			t.Errorf("finding %d (%s) MatchedText not redacted: %q",
				i, findings[i].RuleID, findings[i].MatchedText)
		}
		for j, cl := range findings[i].Context {
			if cl.IsMatch && cl.Content != RedactedPlaceholder {
				t.Errorf("finding %d (%s) context[%d] not redacted: %q",
					i, findings[i].RuleID, j, cl.Content)
			}
		}
	}

	// Negative: a non-sensitive finding outside credential-leak must keep
	// its match text intact. Redacting too eagerly would hide every
	// prompt-injection signature behind [REDACTED].
	if findings[2].MatchedText != "ignore previous instructions" {
		t.Errorf("non-sensitive prompt-injection finding was redacted: %q", findings[2].MatchedText)
	}
}

// TestRedactSensitiveFindings_CustomRuleBackwardCompat ensures a user-written
// rule that still relies on Category == "credential-leak" (no Sensitive flag
// authored in their YAML) keeps redacting. The fix would silently regress
// every custom rule shipped before v0.16.2 if the category fallback were
// dropped.
func TestRedactSensitiveFindings_CustomRuleBackwardCompat(t *testing.T) {
	secret := "AKIAEXAMPLEUSERSAWSKEY"
	findings := []Finding{
		{
			RuleID:      "CRED_999_CUSTOM",
			Category:    "credential-leak",
			Sensitive:   false, // legacy rule, never opted into Sensitive
			MatchedText: secret,
			Context: []ContextLine{
				{Line: 1, Content: "aws_access_key_id = " + secret, IsMatch: true},
			},
		},
	}

	RedactSensitiveFindings(findings)

	if findings[0].MatchedText != RedactedPlaceholder {
		t.Errorf("custom credential-leak rule MatchedText not redacted: %q", findings[0].MatchedText)
	}
	if findings[0].Context[0].Content != RedactedPlaceholder {
		t.Errorf("custom credential-leak rule context not redacted: %q", findings[0].Context[0].Content)
	}
}

// TestRedactCredentialFindings_DeprecatedAlias exercises the old function
// name. Library consumers pinned to the v0.15-and-older API should see
// identical behaviour: the alias delegates to RedactSensitiveFindings.
func TestRedactCredentialFindings_DeprecatedAlias(t *testing.T) {
	findings := []Finding{
		mkFinding("credential-leak", "sk-proj-secret", true),
	}
	RedactCredentialFindings(findings)
	if findings[0].MatchedText != RedactedPlaceholder {
		t.Errorf("deprecated alias did not redact: %q", findings[0].MatchedText)
	}
}

func TestRedactSensitiveFindings_NilSafe(t *testing.T) {
	RedactSensitiveFindings(nil)
	RedactSensitiveFindings([]Finding{})
}

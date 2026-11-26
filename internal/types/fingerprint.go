package types

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Fingerprintable reports whether a finding has a stable fingerprint: one
// that baselines may record and SARIF may publish. It mirrors the redaction
// contract in RedactSensitiveFindings: a finding whose matched text is
// redacted (Sensitive, or the legacy credential-leak category) has none, so a
// fingerprint is only ever computed from matched text that is not a secret.
func Fingerprintable(f Finding) bool {
	return !f.Sensitive && f.Category != "credential-leak"
}

// FindingFingerprint derives the stable identifier baselines, SARIF
// partialFingerprints and the JSON `fingerprint` field share. It hashes the
// rule ID, analyzer, slash-normalized file path and whitespace-normalized
// matched text. Line and column are deliberately excluded so the fingerprint
// survives line churn. Call it only on Fingerprintable findings.
//
// The algorithm is part of the baseline file contract: changing it would
// make every recorded baseline entry and every uploaded code-scanning alert
// look new.
func FindingFingerprint(f Finding) string {
	h := sha256.New()
	// NUL separators so field boundaries cannot be forged by content.
	fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s",
		f.RuleID, f.Analyzer, slashPath(f.FilePath), normalizeSnippet(f.MatchedText))
	return hex.EncodeToString(h.Sum(nil))
}

// slashPath normalizes path separators to forward slashes unconditionally
// (it also rewrites backslashes on a non-Windows host), so a baseline
// written on Windows matches a scan run on Linux or macOS.
func slashPath(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}

// normalizeSnippet collapses runs of whitespace to a single space and trims
// the ends, so reindenting a matched line does not change the fingerprint.
func normalizeSnippet(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

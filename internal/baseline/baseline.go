// Package baseline implements scan baseline / diff mode: a way to gate
// CI only on NEW scan findings, treating findings already recorded in a
// baseline file as accepted.
//
// Baselines apply to SCAN findings only. Known-malicious / compromised
// package findings (aguara check / audit's check phase) are never
// baselineable -- a baseline must not be able to permanently silence a
// confirmed-compromised dependency.
//
// Policy 2B: secret-bearing findings (Sensitive, or the legacy
// credential-leak category) are not baselineable. Their MatchedText is
// redacted before output, so a fingerprint derived from it would either
// persist a hash of a secret to disk or collapse distinct secrets into
// one key. Baselineable() mirrors RedactSensitiveFindings exactly, so
// any finding that gets redacted is excluded from baselining and is
// always reported.
package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/garagon/aguara/internal/types"
)

// FileVersion is the schema version of the baseline file. Load rejects
// any other version rather than guessing how to read it.
const FileVersion = 1

// fingerprintKey is the SARIF partialFingerprints key for the aguara
// fingerprint, also documented for external baseline tooling.
const FingerprintKey = "aguara/v1"

// Baselineable reports whether a finding may be recorded in / matched
// against a baseline. It mirrors the redaction contract in
// types.RedactSensitiveFindings: a finding that would be redacted
// (Sensitive, or the legacy credential-leak category) is never
// baselineable, so a fingerprint is only ever computed from MatchedText
// that is not redacted.
func Baselineable(f types.Finding) bool {
	return !f.Sensitive && f.Category != "credential-leak"
}

// Fingerprint is a stable, redaction-safe identifier for a finding.
type Fingerprint string

// ComputeFingerprint derives a fingerprint from the rule ID, analyzer,
// slash-normalized file path, and normalized matched text. Line and
// column are deliberately excluded so the fingerprint survives line
// churn (a finding that moves from line 5 to line 50 keeps the same
// fingerprint). The analyzer is included so two analyzers that emit the
// same rule ID for the same span stay distinct; the path is
// slash-normalized so a baseline written on Windows matches a scan run
// on Linux/macOS CI. The matched-text component keeps distinct findings
// of the same rule in the same file distinct, so baselining one
// occurrence does not silence a genuinely new one. Only call on
// Baselineable findings.
func ComputeFingerprint(f types.Finding) Fingerprint {
	h := sha256.New()
	// NUL separators so field boundaries cannot be forged by content.
	fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s",
		f.RuleID, f.Analyzer, slashPath(f.FilePath), normalizeSnippet(f.MatchedText))
	return Fingerprint(hex.EncodeToString(h.Sum(nil)))
}

// slashPath normalizes path separators to forward slashes
// unconditionally (filepath.ToSlash semantics, but cross-OS: it also
// rewrites backslashes when run on a non-Windows host). This makes a
// baseline written on Windows match a scan run on Linux/macOS CI for the
// same logical file.
func slashPath(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}

// normalizeSnippet collapses runs of whitespace to a single space and
// trims the ends, so cosmetic reindentation of a matched line does not
// change the fingerprint.
func normalizeSnippet(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// Set is the collection of fingerprints loaded from a baseline file.
type Set struct {
	m map[Fingerprint]struct{}
}

// Contains reports whether fp is present in the baseline.
func (s *Set) Contains(fp Fingerprint) bool {
	_, ok := s.m[fp]
	return ok
}

// Len returns the number of fingerprints in the baseline.
func (s *Set) Len() int { return len(s.m) }

type baselineFile struct {
	Version      int      `json:"version"`
	GeneratedAt  string   `json:"generated_at,omitempty"`
	ToolVersion  string   `json:"tool_version,omitempty"`
	Fingerprints []string `json:"fingerprints"`
}

// Load reads a baseline file. It fails closed: a missing, unreadable, or
// malformed file is an error, never an empty baseline -- a typo'd
// --baseline path must not silently pass every finding as "new".
func Load(path string) (*Set, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("baseline: read %s: %w", path, err)
	}
	var f baselineFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("baseline: parse %s: %w", path, err)
	}
	if f.Version != FileVersion {
		return nil, fmt.Errorf("baseline: %s has version %d, this build understands %d", path, f.Version, FileVersion)
	}
	set := &Set{m: make(map[Fingerprint]struct{}, len(f.Fingerprints))}
	for _, fp := range f.Fingerprints {
		set.m[Fingerprint(fp)] = struct{}{}
	}
	return set, nil
}

// Write writes a baseline file containing the deduplicated, sorted
// fingerprints of every baselineable finding. Non-baselineable findings
// (Sensitive / credential-leak) are skipped; the skipped count is
// returned so the caller can report that they remain non-baselineable.
// Output is sorted so regenerating an unchanged baseline produces an
// identical file.
func Write(path string, findings []types.Finding, toolVersion string) (written, skipped int, err error) {
	seen := map[Fingerprint]struct{}{}
	fps := make([]string, 0, len(findings))
	for _, f := range findings {
		if !Baselineable(f) {
			skipped++
			continue
		}
		fp := ComputeFingerprint(f)
		if _, dup := seen[fp]; dup {
			continue
		}
		seen[fp] = struct{}{}
		fps = append(fps, string(fp))
	}
	sort.Strings(fps)
	out := baselineFile{
		Version:      FileVersion,
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		ToolVersion:  toolVersion,
		Fingerprints: fps,
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return 0, 0, fmt.Errorf("baseline: marshal: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return 0, 0, fmt.Errorf("baseline: write %s: %w", path, err)
	}
	return len(fps), skipped, nil
}

// Apply partitions findings into the gate set (findings that still count
// toward the CI threshold) and a summary describing the partition.
// Baselineable findings whose fingerprint is in the set are suppressed
// from the gate; non-baselineable findings always remain in the gate and
// are counted separately so users understand they are never silenced.
func Apply(findings []types.Finding, set *Set, path string) (gate []types.Finding, summary types.BaselineSummary) {
	summary = types.BaselineSummary{Applied: true, Path: path, Total: len(findings)}
	for _, f := range findings {
		if !Baselineable(f) {
			// Always reported; counted separately, never folded into New.
			summary.NonBaselineable++
			gate = append(gate, f)
			continue
		}
		if set.Contains(ComputeFingerprint(f)) {
			summary.Baselined++
			continue
		}
		summary.New++
		gate = append(gate, f)
	}
	// GateCount is everything that still counts toward the CI threshold:
	// genuinely new baselineable findings plus the always-reported
	// non-baselineable ones.
	summary.GateCount = summary.New + summary.NonBaselineable
	return gate, summary
}

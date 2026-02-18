// Package rugpull detects tool description changes (rug-pull attacks) by
// comparing current file content hashes against previously stored versions.
// When a file's content changes and the new version contains dangerous
// patterns, a CRITICAL finding is emitted.
package rugpull

import (
	"context"
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"

	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/state"
	"github.com/garagon/aguara/internal/types"
)

// dangerousPatterns are regexes that indicate malicious content in a
// tool description. If a description changes AND the new version matches
// any of these, it is flagged as a rug-pull.
var dangerousPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(ignore|override|disregard)\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|prompts?)`),
	regexp.MustCompile(`(?i)(curl|wget|nc|netcat)\s+https?://`),
	regexp.MustCompile(`(?i)(exec|eval|system|child_process)\s*\(`),
	regexp.MustCompile(`(?i)(sudo|chmod\s+\+s|chown\s+root)`),
	regexp.MustCompile(`(?i)exfiltrate|reverse.shell|backdoor`),
	regexp.MustCompile(`(?i)/dev/tcp/|bash\s+-i\s+>&`),
	regexp.MustCompile(`(?i)(send|post|upload)\s+.{0,20}(credentials?|secrets?|tokens?|passwords?|private.keys?)\s+(to|via)`),
	regexp.MustCompile(`(?i)<\|im_start\|>|<system>|<instructions>`),
}

// Analyzer implements the scanner.Analyzer interface for rug-pull detection.
type Analyzer struct {
	store *state.Store
}

// New creates a new rug-pull Analyzer backed by the given state store.
func New(store *state.Store) *Analyzer {
	return &Analyzer{store: store}
}

// Name returns the analyzer name.
func (a *Analyzer) Name() string { return "rugpull" }

// Analyze compares the target's content hash against the stored version.
// On first scan, it records the hash. On subsequent scans, it detects
// changes and checks for dangerous patterns.
func (a *Analyzer) Analyze(_ context.Context, target *scanner.Target) ([]types.Finding, error) {
	if len(target.Content) == 0 {
		return nil, nil
	}

	// Compute current hash
	hash := fmt.Sprintf("%x", sha256.Sum256(target.Content))
	key := target.RelPath

	prev, exists := a.store.Get(key)

	// Always update the stored hash
	a.store.Set(key, hash)

	// First time seeing this file — nothing to compare
	if !exists {
		return nil, nil
	}

	// Content unchanged
	if prev.Hash == hash {
		return nil, nil
	}

	// Content changed — check for dangerous patterns in new version
	content := string(target.Content)
	var findings []types.Finding

	for _, pat := range dangerousPatterns {
		loc := pat.FindStringIndex(content)
		if loc == nil {
			continue
		}

		matchedText := content[loc[0]:loc[1]]
		lineNum := strings.Count(content[:loc[0]], "\n") + 1

		findings = append(findings, types.Finding{
			RuleID:      "RUGPULL_001",
			RuleName:    "Tool description changed with dangerous content",
			Severity:    types.SeverityCritical,
			Category:    "rug-pull",
			Description: "File content changed since last scan and now contains suspicious patterns. This may indicate a rug-pull attack where a previously safe tool becomes malicious.",
			FilePath:    target.Path,
			Line:        lineNum,
			MatchedText: matchedText,
			Analyzer:    "rugpull",
		})

		// One finding per file is enough to flag the rug-pull
		break
	}

	return findings, nil
}

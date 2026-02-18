package pattern

import (
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"
	"unicode"

	"github.com/garagon/aguara/internal/rules"
	"github.com/garagon/aguara/internal/scanner"
)

var (
	base64Re = regexp.MustCompile(`[A-Za-z0-9+/]{16,}={0,2}`)
	hexRe    = regexp.MustCompile(`(?:0x)?[0-9a-fA-F]{16,}`)
)

// DecodeAndRescan detects encoded blobs in content, decodes them, and re-scans with provided rules.
func DecodeAndRescan(target *scanner.Target, compiled []*rules.CompiledRule) []scanner.Finding {
	var findings []scanner.Finding
	content := string(target.Content)
	lines := target.Lines()

	// Scan for base64 blobs
	for _, loc := range base64Re.FindAllStringIndex(content, -1) {
		encoded := content[loc[0]:loc[1]]
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			// try URL-safe
			decoded, err = base64.URLEncoding.DecodeString(encoded)
			if err != nil {
				continue
			}
		}
		if !isPrintable(decoded) || len(decoded) < 8 {
			continue
		}
		line := lineNumberAtOffset(content, loc[0])
		findings = append(findings, rescan(decoded, line, lines, target, compiled, "base64")...)
	}

	// Scan for hex blobs
	for _, loc := range hexRe.FindAllStringIndex(content, -1) {
		encoded := content[loc[0]:loc[1]]
		encoded = strings.TrimPrefix(encoded, "0x")
		if len(encoded)%2 != 0 {
			continue
		}
		decoded, err := hex.DecodeString(encoded)
		if err != nil {
			continue
		}
		if !isPrintable(decoded) || len(decoded) < 8 {
			continue
		}
		line := lineNumberAtOffset(content, loc[0])
		findings = append(findings, rescan(decoded, line, lines, target, compiled, "hex")...)
	}

	return findings
}

func rescan(decoded []byte, origLine int, origLines []string, target *scanner.Target, compiled []*rules.CompiledRule, encoding string) []scanner.Finding {
	var findings []scanner.Finding
	decodedStr := string(decoded)
	decodedLines := strings.Split(decodedStr, "\n")

	for _, rule := range compiled {
		if !matchesTarget(rule.Targets, target.RelPath) {
			continue
		}
		for _, pat := range rule.Patterns {
			hits := matchPattern(pat, decodedStr, decodedLines)
			for _, hit := range hits {
				findings = append(findings, scanner.Finding{
					RuleID:      rule.ID,
					RuleName:    rule.Name + " (decoded " + encoding + ")",
					Severity:    rule.Severity,
					Category:    rule.Category,
					Description: rule.Description,
					FilePath:    target.RelPath,
					Line:        origLine,
					MatchedText: hit.text,
					Context:     extractContext(origLines, origLine, contextRadius),
					Analyzer:    "pattern-decoder",
				})
			}
		}
	}
	return findings
}

func isPrintable(data []byte) bool {
	printable := 0
	for _, b := range data {
		if unicode.IsPrint(rune(b)) || b == '\n' || b == '\r' || b == '\t' {
			printable++
		}
	}
	return float64(printable)/float64(len(data)) > 0.7
}

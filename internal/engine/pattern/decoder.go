package pattern

import (
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"
	"unicode"

	"github.com/garagon/aguara/internal/rules"
	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
)

const (
	// maxEncodedBlobSize is the maximum size of an encoded blob to attempt decoding.
	maxEncodedBlobSize = 1 << 20 // 1 MB
	// maxDecodedSize is the maximum decoded output to re-scan.
	maxDecodedSize = 512 << 10 // 512 KB
)

var (
	base64Re = regexp.MustCompile(`[A-Za-z0-9+/]{16,}={0,2}`)
	hexRe    = regexp.MustCompile(`(?:0x)?[0-9a-fA-F]{16,}`)
)

// DecodeAndRescan detects encoded blobs in content, decodes them, and re-scans with provided rules.
// cbMap is the code block map for the file (nil for non-markdown files).
func DecodeAndRescan(target *scanner.Target, compiled []*rules.CompiledRule, cbMap []bool) []scanner.Finding {
	var findings []scanner.Finding
	content := string(target.Content)
	lines := target.Lines()

	// Scan for base64 blobs
	for _, loc := range base64Re.FindAllStringIndex(content, -1) {
		if loc[1]-loc[0] > maxEncodedBlobSize {
			continue
		}
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
		if len(decoded) > maxDecodedSize {
			decoded = decoded[:maxDecodedSize]
		}
		line := lineNumberAtOffset(content, loc[0])
		findings = append(findings, rescan(decoded, line, lines, target, compiled, "base64", cbMap)...)
	}

	// Scan for hex blobs
	for _, loc := range hexRe.FindAllStringIndex(content, -1) {
		if loc[1]-loc[0] > maxEncodedBlobSize {
			continue
		}
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
		if len(decoded) > maxDecodedSize {
			decoded = decoded[:maxDecodedSize]
		}
		line := lineNumberAtOffset(content, loc[0])
		findings = append(findings, rescan(decoded, line, lines, target, compiled, "hex", cbMap)...)
	}

	return findings
}

func rescan(decoded []byte, origLine int, origLines []string, target *scanner.Target, compiled []*rules.CompiledRule, encoding string, cbMap []bool) []scanner.Finding {
	var findings []scanner.Finding
	decodedStr := string(decoded)
	decodedLines := strings.Split(decodedStr, "\n")

	// Decoded blob inherits code block status from the line where the blob was found
	inCB := isInCodeBlock(cbMap, origLine)

	for _, rule := range compiled {
		if !matchesTarget(rule.Targets, target.RelPath) {
			continue
		}
		for _, pat := range rule.Patterns {
			hits := matchPattern(pat, decodedStr, decodedLines)
			for _, hit := range hits {
				sev := rule.Severity
				if inCB {
					sev = types.DowngradeSeverity(sev)
				}
				findings = append(findings, scanner.Finding{
					RuleID:      rule.ID,
					RuleName:    rule.Name + " (decoded " + encoding + ")",
					Severity:    sev,
					Category:    rule.Category,
					Description: rule.Description,
					FilePath:    target.RelPath,
					Line:        origLine,
					MatchedText: hit.text,
					Context:     extractContext(origLines, origLine, contextRadius),
					Analyzer:    "pattern-decoder",
					InCodeBlock: inCB,
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

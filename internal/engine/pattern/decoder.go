package pattern

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/garagon/aguara/internal/rules"
	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
)

const (
	// maxEncodedBlobSize is the maximum size of an encoded blob to attempt decoding.
	maxEncodedBlobSize = 1 << 20 // 1 MB
	// maxDecodedSize is the maximum decoded output to re-scan.
	maxDecodedSize = 512 << 10 // 512 KB
	// maxBlobsPerFile caps the number of encoded blobs rescanned per file
	// to avoid quadratic behavior on files with many short encoded strings.
	maxBlobsPerFile = 10
)

var (
	base64Re        = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)
	hexRe           = regexp.MustCompile(`(?:0x)?[0-9a-fA-F]{32,}`)
	urlEncodedRe    = regexp.MustCompile(`(%[0-9a-fA-F]{2}){3,}`)
	unicodeEscapeRe = regexp.MustCompile(`(\\u[0-9a-fA-F]{4}){3,}`)
	hexEscapeRe     = regexp.MustCompile(`(\\x[0-9a-fA-F]{2}){3,}`)
	htmlEntityRe    = regexp.MustCompile(`(&#x?[0-9a-fA-F]+;){3,}`)
)

// DecodeAndRescan detects encoded blobs in content, decodes them, and re-scans with provided rules.
// cbMap is the code block map for the file (nil for non-markdown files).
// The maxBlobsPerFile cap is shared across ALL decoder types.
func DecodeAndRescan(target *scanner.Target, compiled []*rules.CompiledRule, cbMap []bool) []scanner.Finding {
	var findings []scanner.Finding
	content := target.StringContent()
	lines := target.Lines()
	blobCount := 0

	// Scan for base64 blobs (cap regex matches to avoid computing all when only maxBlobsPerFile are used)
	for _, loc := range base64Re.FindAllStringIndex(content, maxBlobsPerFile*3) {
		if blobCount >= maxBlobsPerFile {
			break
		}
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
		blobCount++
		line := lineNumberAtOffset(content, loc[0])
		findings = append(findings, rescan(decoded, line, lines, target, compiled, "base64", cbMap)...)
	}

	// Scan for hex blobs
	for _, loc := range hexRe.FindAllStringIndex(content, maxBlobsPerFile*3) {
		if blobCount >= maxBlobsPerFile {
			break
		}
		if loc[1]-loc[0] > maxEncodedBlobSize {
			continue
		}
		encoded := content[loc[0]:loc[1]]
		if isCryptoAddress(encoded) {
			continue
		}
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
		blobCount++
		line := lineNumberAtOffset(content, loc[0])
		findings = append(findings, rescan(decoded, line, lines, target, compiled, "hex", cbMap)...)
	}

	// Scan for URL-encoded blobs
	for _, loc := range urlEncodedRe.FindAllStringIndex(content, maxBlobsPerFile*3) {
		if blobCount >= maxBlobsPerFile {
			break
		}
		if loc[1]-loc[0] > maxEncodedBlobSize {
			continue
		}
		decoded, err := decodeURLEncoded(content[loc[0]:loc[1]])
		if err != nil || !isPrintable(decoded) || len(decoded) < 8 {
			continue
		}
		if len(decoded) > maxDecodedSize {
			decoded = decoded[:maxDecodedSize]
		}
		blobCount++
		line := lineNumberAtOffset(content, loc[0])
		findings = append(findings, rescan(decoded, line, lines, target, compiled, "url-encoded", cbMap)...)
	}

	// Scan for Unicode escape blobs (\uXXXX)
	for _, loc := range unicodeEscapeRe.FindAllStringIndex(content, maxBlobsPerFile*3) {
		if blobCount >= maxBlobsPerFile {
			break
		}
		if loc[1]-loc[0] > maxEncodedBlobSize {
			continue
		}
		decoded, err := decodeUnicodeEscape(content[loc[0]:loc[1]])
		if err != nil || !isPrintable(decoded) || len(decoded) < 8 {
			continue
		}
		if len(decoded) > maxDecodedSize {
			decoded = decoded[:maxDecodedSize]
		}
		blobCount++
		line := lineNumberAtOffset(content, loc[0])
		findings = append(findings, rescan(decoded, line, lines, target, compiled, "unicode-escape", cbMap)...)
	}

	// Scan for hex escape blobs (\xXX)
	for _, loc := range hexEscapeRe.FindAllStringIndex(content, maxBlobsPerFile*3) {
		if blobCount >= maxBlobsPerFile {
			break
		}
		if loc[1]-loc[0] > maxEncodedBlobSize {
			continue
		}
		decoded, err := decodeHexEscape(content[loc[0]:loc[1]])
		if err != nil || !isPrintable(decoded) || len(decoded) < 8 {
			continue
		}
		if len(decoded) > maxDecodedSize {
			decoded = decoded[:maxDecodedSize]
		}
		blobCount++
		line := lineNumberAtOffset(content, loc[0])
		findings = append(findings, rescan(decoded, line, lines, target, compiled, "hex-escape", cbMap)...)
	}

	// Scan for HTML entity blobs (&#XX; or &#xXX;)
	for _, loc := range htmlEntityRe.FindAllStringIndex(content, maxBlobsPerFile*3) {
		if blobCount >= maxBlobsPerFile {
			break
		}
		if loc[1]-loc[0] > maxEncodedBlobSize {
			continue
		}
		decoded, err := decodeHTMLEntities(content[loc[0]:loc[1]])
		if err != nil || !isPrintable(decoded) || len(decoded) < 8 {
			continue
		}
		if len(decoded) > maxDecodedSize {
			decoded = decoded[:maxDecodedSize]
		}
		blobCount++
		line := lineNumberAtOffset(content, loc[0])
		findings = append(findings, rescan(decoded, line, lines, target, compiled, "html-entity", cbMap)...)
	}

	return findings
}

// decodeURLEncoded decodes percent-encoded strings (e.g., %49%67%6E%6F%72%65).
func decodeURLEncoded(s string) ([]byte, error) {
	decoded, err := url.QueryUnescape(s)
	if err != nil {
		return nil, err
	}
	return []byte(decoded), nil
}

// decodeUnicodeEscape decodes \uXXXX sequences (e.g., \u0049\u0067\u006E).
func decodeUnicodeEscape(s string) ([]byte, error) {
	var buf []byte
	for len(s) > 0 {
		if len(s) >= 6 && s[0] == '\\' && s[1] == 'u' {
			codePoint, err := strconv.ParseUint(s[2:6], 16, 32)
			if err != nil {
				return nil, err
			}
			var runeBytes [4]byte
			n := utf8.EncodeRune(runeBytes[:], rune(codePoint))
			buf = append(buf, runeBytes[:n]...)
			s = s[6:]
		} else {
			buf = append(buf, s[0])
			s = s[1:]
		}
	}
	return buf, nil
}

// decodeHexEscape decodes \xXX sequences (e.g., \x49\x67\x6E\x6F\x72\x65).
func decodeHexEscape(s string) ([]byte, error) {
	var buf []byte
	for len(s) > 0 {
		if len(s) >= 4 && s[0] == '\\' && s[1] == 'x' {
			b, err := hex.DecodeString(s[2:4])
			if err != nil {
				return nil, err
			}
			buf = append(buf, b...)
			s = s[4:]
		} else {
			buf = append(buf, s[0])
			s = s[1:]
		}
	}
	return buf, nil
}

// decodeHTMLEntities decodes numeric HTML entities (&#73; decimal, &#x49; hex).
func decodeHTMLEntities(s string) ([]byte, error) {
	var buf []byte
	for len(s) > 0 {
		if s[0] == '&' && len(s) >= 4 && s[1] == '#' {
			end := strings.Index(s, ";")
			if end == -1 {
				buf = append(buf, s[0])
				s = s[1:]
				continue
			}
			numStr := s[2:end]
			var codePoint uint64
			var err error
			if len(numStr) > 0 && (numStr[0] == 'x' || numStr[0] == 'X') {
				codePoint, err = strconv.ParseUint(numStr[1:], 16, 32)
			} else {
				codePoint, err = strconv.ParseUint(numStr, 10, 32)
			}
			if err != nil {
				return nil, fmt.Errorf("invalid HTML entity: %s", s[:end+1])
			}
			var runeBytes [4]byte
			n := utf8.EncodeRune(runeBytes[:], rune(codePoint))
			buf = append(buf, runeBytes[:n]...)
			s = s[end+1:]
		} else {
			buf = append(buf, s[0])
			s = s[1:]
		}
	}
	return buf, nil
}

func rescan(decoded []byte, origLine int, origLines []string, target *scanner.Target, compiled []*rules.CompiledRule, encoding string, cbMap []bool) []scanner.Finding {
	var findings []scanner.Finding
	decodedStr := string(decoded)
	lowerDecoded := strings.ToLower(decodedStr)
	decodedLines := strings.Split(decodedStr, "\n")

	// Decoded blob inherits code block status from the line where the blob was found
	inCB := isInCodeBlock(cbMap, origLine)

	for _, rule := range compiled {
		for _, pat := range rule.Patterns {
			hits := matchPattern(pat, decodedStr, lowerDecoded, decodedLines)
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
					Context:     types.ExtractContext(origLines, origLine, ctxRadius, ctxRadius),
					Analyzer:    "pattern-decoder",
					InCodeBlock: inCB,
					Confidence:  0.90,
				})
			}
		}
	}
	return findings
}

// cryptoAddrRe matches common cryptocurrency address formats that should not
// be treated as hex-encoded payloads.
var cryptoAddrRe = regexp.MustCompile(
	`^(?:` +
		`0x[0-9a-fA-F]{40}` + // Ethereum (42 chars with 0x)
		`|0x[0-9a-fA-F]{64}` + // Ethereum tx hashes (66 chars with 0x)
		`)$`)

// isCryptoAddress returns true if the hex blob looks like a cryptocurrency address.
func isCryptoAddress(s string) bool {
	return cryptoAddrRe.MatchString(s)
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

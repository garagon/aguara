package pattern

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/garagon/aguara/internal/rules"
	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
)

// Decoded content.
//
// The matcher looks for blobs in eight encodings, decodes every blob whose
// decoded bytes read as text and matches that text against the rules that
// apply to the file the blob came from, with the same semantics as the
// file's own text: match modes, within_lines windows, exclude scopes and
// the keyword prefilter. Findings keep the rule's ID, severity, category
// and remediation; the rule name ends with "(decoded <encoding>)", the
// analyzer is "pattern-decoder", and the line is where the encoded text
// sits in the file.
//
// A blob is matched together with up to decodedContextBytes of its own line
// on each side, so a rule written for the file's syntax (a JSON key, a YAML
// key) still sees the key in front of an encoded value. Only matches that
// touch the decoded text are reported; the surrounding text was already
// matched as part of the file.
//
// Base64 wrapped over several lines of one width (MIME, PEM bodies,
// indented YAML block scalars) is joined before decoding. Decoded text is
// searched once more for blobs (base64 of base64, URL-encoded or hex
// base64), up to maxDecodeDepth levels in all.
//
// Work is bounded per file. Each encoding rescans at most decoderBlobBudget
// blobs, nested ones included, and the decoded text rescanned for the
// whole file is at most decodedBytesFactor times the file size, plus at most
// 2*decodedContextBytes of line context per blob. Only blobs that decode to
// text count: hashes, integrity values and other binary encodings are
// decoded, fail the text test and cost nothing from either budget, so a
// lockfile full of them cannot exhaust it. Finding candidates and decoding
// them is linear in the file size for each encoding.

const (
	// maxEncodedBlobSize is the maximum size of an encoded blob to attempt decoding.
	maxEncodedBlobSize = 1 << 20 // 1 MB
	// maxDecodedSize is the maximum decoded output to re-scan.
	maxDecodedSize = 512 << 10 // 512 KB
	// minDecodedSize is the shortest decoded text worth matching.
	minDecodedSize = 8
	// decoderBlobBudget is how many decoded blobs each encoding may rescan
	// per file, nested blobs included.
	decoderBlobBudget = 256
	// decodedBytesFactor bounds the decoded text rescanned per file, as a
	// multiple of the file size. Every decoder's output is at most as long as
	// its input, so one level of blobs of one encoding never needs more than
	// the file size; the factor leaves room for nested blobs and for regions
	// that read as text in two encodings.
	decodedBytesFactor = 2
	// maxDecodeDepth is how many encodings deep the decoder goes: a blob in
	// the file, then a blob inside its decoded text.
	maxDecodeDepth = 2
	// decodedContextBytes is how much of the blob's own line is matched
	// with the decoded text on each side.
	decodedContextBytes = 256
	// minWrapWidth is the narrowest line a wrapped base64 block may use.
	minWrapWidth = 16
	// minBase64Length is the shortest base64 blob the decoder considers,
	// on one line or joined from several.
	minBase64Length = 40
	// decodedConfidence is the confidence of a finding in decoded text.
	decodedConfidence = 0.90
)

var (
	base64Re        = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)
	hexRe           = regexp.MustCompile(`(?:0x)?[0-9a-fA-F]{32,}`)
	urlEncodedRe    = regexp.MustCompile(`(%[0-9a-fA-F]{2}){3,}`)
	unicodeEscapeRe = regexp.MustCompile(`(\\u[0-9a-fA-F]{4}){3,}`)
	hexEscapeRe     = regexp.MustCompile(`(\\x[0-9a-fA-F]{2}){3,}`)
	htmlEntityRe    = regexp.MustCompile(`(&#x?[0-9a-fA-F]+;){3,}`)
	// base32Re matches RFC 4648 base32 blobs. Alphabet is A-Z + 2-7 with
	// optional = padding. Min length 40 prevents matching ALL_CAPS identifiers.
	base32Re = regexp.MustCompile(`[A-Z2-7]{40,}={0,6}`)
	// octalEscapeRe matches C-style octal escapes: \NNN where N is 0-7 and
	// the first digit is 0-3 to bound the byte value to 0-255. Requires 4+
	// contiguous escapes to avoid matching incidental \NNN literals in prose.
	octalEscapeRe = regexp.MustCompile(`(\\[0-3][0-7]{2}){4,}`)
)

// encoding identifies one of the decoders. The order is the order in which
// the decoders run over a text.
type encoding uint8

const (
	encBase64 encoding = iota
	encHex
	encURL
	encUnicodeEscape
	encHexEscape
	encHTMLEntity
	encBase32
	encOctalEscape
	encodingCount
)

var encodingNames = [encodingCount]string{
	"base64", "hex", "url-encoded", "unicode-escape", "hex-escape", "html-entity", "base32", "octal-escape",
}

var encodingPatterns = [encodingCount]*regexp.Regexp{
	base64Re, hexRe, urlEncodedRe, unicodeEscapeRe, hexEscapeRe, htmlEntityRe, base32Re, octalEscapeRe,
}

// DecodeAndRescan detects encoded blobs in content, decodes them and
// matches the decoded text against those of the compiled rules that apply
// to the target, exactly as Matcher.Analyze does for decoded content.
// cbMap is the code block map for the file (nil for non-markdown files).
func DecodeAndRescan(target *scanner.Target, compiled []*rules.CompiledRule, cbMap []bool) []scanner.Finding {
	m := NewMatcher(compiled)
	keys := lookupKeys(target.RelPath)
	findings, _ := m.decodeAndRescan(context.Background(), target, m.rulesForFile(target.RelPath, keys), keys, cbMap, true)
	return findings
}

// decodeAndRescan runs the decoders over the target and returns the
// findings in decoded content. prefilter selects the keyword prefilter for
// the decoded texts, as in matchText.
func (m *Matcher) decodeAndRescan(ctx context.Context, target *scanner.Target, applicable []*rules.CompiledRule, keys []string, cbMap []bool, prefilter bool) ([]scanner.Finding, error) {
	run := m.newDecodeRun(ctx, target, applicable, keys, cbMap, prefilter)
	run.run()
	return run.findings, run.err
}

func (m *Matcher) newDecodeRun(ctx context.Context, target *scanner.Target, applicable []*rules.CompiledRule, keys []string, cbMap []bool, prefilter bool) *decodeRun {
	run := &decodeRun{
		m:          m,
		ctx:        ctx,
		target:     target,
		content:    target.StringContent(),
		lines:      target.Lines(),
		applicable: applicable,
		keys:       keys,
		cbMap:      cbMap,
		downgrade:  cbMap != nil && !types.IsAgentDirectiveFile(target.RelPath),
		prefilter:  prefilter,
	}
	run.bytesLeft = decodedBytesFactor * len(run.content)
	for i := range run.blobsLeft {
		run.blobsLeft[i] = decoderBlobBudget
	}
	return run
}

// run decodes the blobs of every encoding in the file's content.
func (r *decodeRun) run() {
	for enc := range encodingCount {
		if r.stopped() {
			break
		}
		r.scanText(r.content, enc, nil, 1, "")
	}
}

// decodeRun holds the state of the decoders over one file.
type decodeRun struct {
	m          *Matcher
	ctx        context.Context
	target     *scanner.Target
	content    string
	lines      []string
	applicable []*rules.CompiledRule
	keys       []string
	cbMap      []bool
	downgrade  bool
	prefilter  bool

	blobsLeft [encodingCount]int
	bytesLeft int
	// decodeInput counts the encoded bytes handed to a decoder, the
	// candidate-side work, which tests bound.
	decodeInput int

	findings []scanner.Finding
	reported map[decodedFindingKey]bool
	err      error
}

type decodedFindingKey struct {
	rule string
	line int
}

func (r *decodeRun) stopped() bool {
	if r.err == nil && r.ctx.Err() != nil {
		r.err = r.ctx.Err()
	}
	return r.err != nil || r.bytesLeft <= 0
}

// blobOrigin locates a decoded blob in the file. A blob found in the file
// has no parent and records the line it starts on (and, when joined from a
// wrapped block, the block); a nested blob records its offset in the
// decoded text of its parent.
type blobOrigin struct {
	parent *blobOrigin
	start  int // offset of the encoded blob in the parent's decoded text
	enc    encoding
	skip   int // bytes before the encoded data, such as a "0x" prefix
	line   int // source line of the blob, for a blob found in the file
	width  int // line width of a wrapped block, 0 for a one-line blob
	nlines int // number of lines of a wrapped block
}

// sourceLine returns the source line of the encoded bytes that decoded to
// offset d of the blob's decoded text. Fixed-ratio encodings (base64, hex,
// base32) map an offset to its own encoded position; escapes map to the
// start of the blob.
func (o *blobOrigin) sourceLine(d int) int {
	rel := o.skip
	switch o.enc {
	case encBase64:
		rel += d / 3 * 4
	case encHex:
		rel += 2 * d
	case encBase32:
		rel += d / 5 * 8
	}
	if o.parent != nil {
		return o.parent.sourceLine(o.start + rel)
	}
	if o.width > 0 {
		return o.line + min(rel/o.width, o.nlines-1)
	}
	return o.line
}

// candidate is an encoded blob found in a text.
type candidate struct {
	start, end int    // byte range in the searched text
	encoded    string // the encoded data, joined for a wrapped block
	width      int    // line width of a wrapped block
	nlines     int    // lines of a wrapped block
}

// scanText decodes the blobs of one encoding in text, rescans each one that
// reads as text and, below maxDecodeDepth, searches its decoded text for
// further blobs. parent is nil for the file's own content.
func (r *decodeRun) scanText(text string, enc encoding, parent *blobOrigin, depth int, label string) {
	cursor := lineCursor{text: text, line: 1}
	r.forEachCandidate(text, enc, func(c candidate) bool {
		if r.stopped() || r.blobsLeft[enc] == 0 {
			return false
		}
		r.decodeInput += len(c.encoded)
		decoded, ok := decodeBlob(enc, c.encoded)
		if !ok || len(decoded) < minDecodedSize || !isLikelyText(decoded) {
			return true
		}
		if len(decoded) > maxDecodedSize {
			decoded = decoded[:maxDecodedSize]
		}
		if len(decoded) > r.bytesLeft {
			decoded = decoded[:r.bytesLeft]
		}
		r.blobsLeft[enc]--
		r.bytesLeft -= len(decoded)

		origin := &blobOrigin{parent: parent, start: c.start, enc: enc, width: c.width, nlines: c.nlines}
		if enc == encHex && strings.HasPrefix(c.encoded, "0x") {
			origin.skip = 2
		}
		if parent == nil {
			origin.line = cursor.lineAt(c.start)
		}
		blobLabel := encodingNames[enc]
		if label != "" {
			blobLabel = label + "+" + blobLabel
		}
		decodedText := norm.NFKC.String(string(decoded))
		var prefix, suffix string
		if c.width == 0 {
			prefix, suffix = lineContext(text, c.start, c.end)
		}
		r.rescan(prefix, decodedText, suffix, origin, blobLabel)
		if depth < maxDecodeDepth {
			for inner := range encodingCount {
				if r.stopped() {
					break
				}
				r.scanText(decodedText, inner, origin, depth+1, blobLabel)
			}
		}
		return true
	})
}

// forEachCandidate calls fn for each blob of enc in text, in text order,
// until fn returns false. Base64 blocks wrapped over several lines are
// offered as one joined candidate; when the joined block does not decode to
// text, its lines are offered one by one as before.
func (r *decodeRun) forEachCandidate(text string, enc encoding, fn func(candidate) bool) {
	re := encodingPatterns[enc]
	var blocks []candidate
	if enc == encBase64 {
		blocks = wrappedBase64Blocks(text)
	}
	coveredEnd := -1 // end of the last wrapped block that decoded to text
	next := 0        // next block to offer
	offerBlocksBefore := func(pos int) bool {
		for next < len(blocks) && blocks[next].start <= pos {
			b := blocks[next]
			next++
			b.encoded = joinLines(text[b.start:b.end])
			left := r.blobsLeft[enc]
			if !fn(b) {
				return false
			}
			if r.blobsLeft[enc] < left {
				coveredEnd = b.end
			}
		}
		return true
	}
	for pos := 0; pos < len(text); {
		start, end, ok := nextBlob(enc, re, text, pos)
		if !ok {
			break
		}
		pos = end
		if !offerBlocksBefore(start) {
			return
		}
		if start < coveredEnd || end-start > maxEncodedBlobSize {
			continue
		}
		if !fn(candidate{start: start, end: end, encoded: text[start:end]}) {
			return
		}
	}
	offerBlocksBefore(len(text))
}

// nextBlob returns the next match of enc's pattern in text at or after pos.
// The three patterns that are a run of one character class (base64, base32
// and hex) are matched by a byte scan that gives the same leftmost-first
// matches as the regular expression (TestBlobScannersMatchPatterns) without
// its automaton, which costs most of the decoder's time on a file full of
// such runs. pos must be 0 or the end of the previous match.
func nextBlob(enc encoding, re *regexp.Regexp, text string, pos int) (start, end int, ok bool) {
	switch enc {
	case encBase64:
		return nextRun(text, pos, &base64Class, minBase64Length, 2)
	case encBase32:
		return nextRun(text, pos, &base32Class, 40, 6)
	case encHex:
		start, end, ok = nextRun(text, pos, &hexClass, 32, 0)
		// `(?:0x)?` takes a "0x" right before the run unless a previous
		// match already used it.
		if ok && start-2 >= pos && text[start-2] == '0' && text[start-1] == 'x' {
			start -= 2
		}
		return start, end, ok
	}
	loc := re.FindStringIndex(text[pos:])
	if loc == nil {
		return 0, 0, false
	}
	return pos + loc[0], pos + loc[1], true
}

// nextRun finds the first maximal run of class bytes at or after pos that
// is at least min long, followed by up to maxPad '=' bytes.
func nextRun(text string, pos int, class *[256]bool, minLen, maxPad int) (start, end int, ok bool) {
	for i := pos; i < len(text); {
		if !class[text[i]] {
			i++
			continue
		}
		j := i + 1
		for j < len(text) && class[text[j]] {
			j++
		}
		if j-i >= minLen {
			k := j
			for k < len(text) && k-j < maxPad && text[k] == '=' {
				k++
			}
			return i, k, true
		}
		i = j
	}
	return 0, 0, false
}

var base64Class, base32Class, hexClass = byteClass("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"),
	byteClass("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"), byteClass("0123456789abcdefABCDEF")

func byteClass(chars string) [256]bool {
	var class [256]bool
	for i := 0; i < len(chars); i++ {
		class[chars[i]] = true
	}
	return class
}

// wrappedBase64Blocks returns the base64 blocks of text that are wrapped
// over two or more consecutive lines: every line but the last holds only
// base64 alphabet characters, at least minWrapWidth of them and all the
// same number, and the last line holds at most that many, optionally ending
// in padding. Leading and trailing blanks of each line are ignored, so
// indented blocks qualify. The candidates carry spans only; joinLines builds
// a block's encoded text when it is offered, so memory stays bounded by one
// block whatever the number of blocks.
func wrappedBase64Blocks(text string) []candidate {
	var blocks []candidate
	start, end, width, nlines, joined := 0, 0, 0, 0, 0
	flush := func() {
		if nlines >= 2 && joined >= minBase64Length && joined <= maxEncodedBlobSize {
			blocks = append(blocks, candidate{start: start, end: end, width: width, nlines: nlines})
		}
		nlines, joined = 0, 0
	}
	for off := 0; off <= len(text); {
		nl := strings.IndexByte(text[off:], '\n')
		lineEnd := len(text)
		if nl >= 0 {
			lineEnd = off + nl
		}
		ts, te := off, lineEnd
		for ts < te && (text[ts] == ' ' || text[ts] == '\t') {
			ts++
		}
		for te > ts && (text[te-1] == ' ' || text[te-1] == '\t' || text[te-1] == '\r') {
			te--
		}
		n, pad, ok := base64LineShape(text[ts:te])
		if nlines > 0 {
			switch {
			case ok && pad == 0 && n == width:
				end, nlines, joined = te, nlines+1, joined+n
			case ok && n > 0 && n <= width:
				end, nlines, joined = te, nlines+1, joined+n
				flush()
				ok = false // the closing line cannot start a block
			default:
				flush()
			}
		}
		if nlines == 0 && ok && pad == 0 && n >= minWrapWidth {
			start, end, width, nlines, joined = ts, te, n, 1, n
		}
		if nl < 0 {
			break
		}
		off = lineEnd + 1
	}
	flush()
	return blocks
}

// joinLines returns a wrapped block's span without the line breaks and the
// blanks around each line.
func joinLines(span string) string {
	var b strings.Builder
	b.Grow(len(span))
	for i := 0; i < len(span); i++ {
		switch span[i] {
		case '\n', '\r', ' ', '\t':
		default:
			b.WriteByte(span[i])
		}
	}
	return b.String()
}

// base64LineShape reports whether s is base64 alphabet characters followed
// by at most two '=', with the length and the padding count.
func base64LineShape(s string) (n, pad int, ok bool) {
	for n < len(s) && isBase64Char(s[n]) {
		n++
	}
	for n+pad < len(s) && s[n+pad] == '=' {
		pad++
	}
	return n + pad, pad, n+pad == len(s) && pad <= 2
}

func isBase64Char(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/'
}

// lineContext returns up to decodedContextBytes of text before start and
// after end on the same line.
func lineContext(text string, start, end int) (prefix, suffix string) {
	lineStart := strings.LastIndexByte(text[:start], '\n') + 1
	lineStart = max(lineStart, start-decodedContextBytes)
	lineEnd := len(text)
	if nl := strings.IndexByte(text[end:], '\n'); nl >= 0 {
		lineEnd = end + nl
	}
	lineEnd = min(lineEnd, end+decodedContextBytes)
	return text[lineStart:start], text[end:lineEnd]
}

// rescan matches prefix+decoded+suffix against the applicable rules and
// reports the matches that touch the decoded text.
func (r *decodeRun) rescan(prefix, decoded, suffix string, origin *blobOrigin, label string) {
	text := prefix + decoded + suffix
	from, to := len(prefix), len(prefix)+len(decoded)
	touchesDecoded := func(h matchHit) bool { return h.start < to && h.end > from }
	lines := strings.Split(text, "\n")
	matches, err := r.m.matchText(r.ctx, r.applicable, r.keys, text, newLowercaseContent(text), lines, r.target, touchesDecoded, r.prefilter)
	if err != nil {
		r.err = err
	}
	// sourceLineAt maps an offset of text to a source line: offsets in the
	// surrounding line context fall on the blob's first or last line.
	sourceLineAt := func(off int) int {
		return origin.sourceLine(min(max(off-from, 0), max(to-from-1, 0)))
	}
	for _, rm := range matches {
		rule := rm.rule
		line := sourceLineAt(rm.hits[0].start)
		key := decodedFindingKey{rule.ID, line}
		if r.reported[key] {
			continue
		}
		if r.reported == nil {
			r.reported = make(map[decodedFindingKey]bool)
		}
		r.reported[key] = true
		sev := rule.Severity
		inCB := isInCodeBlock(r.cbMap, line)
		if inCB && r.downgrade {
			sev = types.DowngradeSeverity(sev)
		}
		finding := scanner.Finding{
			RuleID:      rule.ID,
			RuleName:    rule.Name + " (decoded " + label + ")",
			Severity:    sev,
			Category:    rule.Category,
			Description: rule.Description,
			Remediation: rule.Remediation,
			FilePath:    r.target.RelPath,
			Line:        line,
			MatchedText: rm.matchedText(),
			Context:     types.ExtractContext(r.lines, line, ctxRadius, ctxRadius),
			Analyzer:    "pattern-decoder",
			InCodeBlock: inCB,
			Sensitive:   rule.Sensitive,
			Confidence:  decodedConfidence,
		}
		for _, hit := range rm.hits {
			finding.AddEvidenceRange(sourceLineAt(hit.start), sourceLineAt(max(hit.end-1, hit.start)))
		}
		r.findings = append(r.findings, finding)
	}
}

// lineCursor returns the 1-based line of increasing offsets of text in
// time linear in the text.
type lineCursor struct {
	text string
	off  int
	line int
}

func (c *lineCursor) lineAt(off int) int {
	if off > c.off {
		c.line += strings.Count(c.text[c.off:off], "\n")
		c.off = off
	}
	return c.line
}

// decodeBlob decodes one candidate of enc.
func decodeBlob(enc encoding, s string) ([]byte, bool) {
	var (
		decoded []byte
		err     error
	)
	switch enc {
	case encBase64:
		decoded, err = base64.StdEncoding.DecodeString(s)
		if err != nil {
			decoded, err = base64.URLEncoding.DecodeString(s)
		}
	case encHex:
		if isCryptoAddress(s) {
			return nil, false
		}
		s = strings.TrimPrefix(s, "0x")
		if len(s)%2 != 0 {
			return nil, false
		}
		decoded, err = hex.DecodeString(s)
	case encURL:
		decoded, err = decodeURLEncoded(s)
	case encUnicodeEscape:
		decoded, err = decodeUnicodeEscape(s)
	case encHexEscape:
		decoded, err = decodeHexEscape(s)
	case encHTMLEntity:
		decoded, err = decodeHTMLEntities(s)
	case encBase32:
		decoded, err = decodeBase32(s)
	case encOctalEscape:
		decoded, err = decodeOctalEscape(s)
	}
	return decoded, err == nil
}

// decodeURLEncoded decodes percent-encoded strings (e.g., %49%67%6E%6F%72%65).
func decodeURLEncoded(s string) ([]byte, error) {
	decoded, err := url.QueryUnescape(s)
	if err != nil {
		return nil, err
	}
	return []byte(decoded), nil
}

// decodeUnicodeEscape decodes \uXXXX sequences (e.g., Ign).
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

// decodeBase32 decodes RFC 4648 base32 strings. Tries the strict StdEncoding
// first, then falls back to NoPadding for blobs that omitted the = chars.
func decodeBase32(s string) ([]byte, error) {
	decoded, err := base32.StdEncoding.DecodeString(s)
	if err == nil {
		return decoded, nil
	}
	stripped := strings.TrimRight(s, "=")
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(stripped)
}

// decodeOctalEscape decodes C-style \NNN sequences (e.g. \150\145\154\154\157
// for "hello"). Each escape is exactly three octal digits with first digit 0-3
// to keep byte values in 0-255.
func decodeOctalEscape(s string) ([]byte, error) {
	var buf []byte
	for len(s) > 0 {
		if len(s) >= 4 && s[0] == '\\' &&
			s[1] >= '0' && s[1] <= '3' &&
			s[2] >= '0' && s[2] <= '7' &&
			s[3] >= '0' && s[3] <= '7' {
			v, err := strconv.ParseUint(s[1:4], 8, 16)
			if err != nil {
				return nil, err
			}
			buf = append(buf, byte(v))
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

// Decoded bytes read as text when at least minTextRatioNum/minTextRatioDen
// of their characters are text characters (see isTextRune). The bytes are
// read as UTF-8 and each byte that is not part of a valid sequence counts
// as one character that is not text, so a few invalid bytes lower the ratio
// instead of rejecting the blob.
//
// Text payloads (prose, commands, JSON, scripts) score 95 percent or more.
// Random bytes score about 40 percent: printable ASCII is 98 of 256 byte
// values, and most bytes from 0x80 up do not form valid UTF-8 sequences.
// At 80 percent, about 1 in 500 random 16-byte values passes, 1 in 70,000
// at 32 bytes, and none of 2,000,000 samples at 48 bytes or more. (Before,
// bytes 0xA0 to 0xFF counted as printable, so about two thirds of random
// values passed and hashes used up the blob budget.)
//
// Hash and integrity values, the most common encoded data in lockfiles and
// manifests, decode to exactly the length of a digest. Decoded text of one
// of those lengths must be text throughout, which about 1 in 400,000
// random 16-byte values and none of 2,000,000 at the longer digest lengths
// manage (TestIsLikelyTextRejectsRandomBytes). A payload of that length
// written as text still passes.
const (
	minTextRatioNum = 4
	minTextRatioDen = 5
)

// isDigestLength reports whether n is the size in bytes of a common digest:
// MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512.
func isDigestLength(n int) bool {
	switch n {
	case 16, 20, 28, 32, 48, 64:
		return true
	}
	return false
}

// isLikelyText reports whether decoded bytes read as text.
func isLikelyText(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	text, total := 0, 0
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		i += size
		total++
		if (r != utf8.RuneError || size > 1) && isTextRune(r) {
			text++
		}
	}
	if isDigestLength(len(data)) {
		return text == total
	}
	return text*minTextRatioDen >= total*minTextRatioNum
}

// isTextRune reports whether r is a printable character, whitespace (any
// Unicode separator included) or a format character such as a zero-width
// space or a bidirectional control. Separators and format characters can
// be invisible but are text, and the unicode-attack rules look for them in
// decoded content too.
func isTextRune(r rune) bool {
	switch r {
	case '\n', '\r', '\t':
		return true
	}
	return unicode.IsPrint(r) || unicode.In(r, unicode.Z, unicode.Cf)
}

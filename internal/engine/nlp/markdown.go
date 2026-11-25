package nlp

import (
	"bytes"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/text"
)

// SectionType represents the type of a markdown section.
type SectionType int

const (
	SectionHeading SectionType = iota
	SectionParagraph
	SectionCodeBlock
	SectionHTMLComment
	SectionListItem
)

func (s SectionType) String() string {
	switch s {
	case SectionHeading:
		return "heading"
	case SectionParagraph:
		return "paragraph"
	case SectionCodeBlock:
		return "code_block"
	case SectionHTMLComment:
		return "html_comment"
	case SectionListItem:
		return "list_item"
	default:
		return "unknown"
	}
}

// MarkdownSection represents a parsed section of a markdown document.
type MarkdownSection struct {
	Type     SectionType
	Text     string
	Line     int    // 1-based line number
	Language string // for code blocks
	Level    int    // for headings
}

// mdParser is a package-level goldmark instance reused across calls.
// goldmark.New() is stateless and safe for concurrent use.
var mdParser = goldmark.New()

// ParseMarkdown extracts structured sections from markdown content.
func ParseMarkdown(source []byte) []MarkdownSection {
	source = blankFrontmatterDelimiters(source)
	reader := text.NewReader(source)
	doc := mdParser.Parser().Parse(reader)

	var sections []MarkdownSection
	walkNode(doc, source, &sections, source)
	return sections
}

// blankFrontmatterDelimiters returns source with the two delimiter lines of
// a leading YAML frontmatter block ("---" ... "---" or "...") overwritten
// with spaces. SKILL.md files, Cursor .mdc rules and other agent
// instruction files start with such a block, but CommonMark has no
// frontmatter: the opening "---" parses as a thematic break and the
// closing one turns the metadata into a setext heading, which made the
// heading checks compare "globs: ... alwaysApply: false" against the body.
// Blanking only the delimiters keeps every byte offset and line number and
// leaves the metadata as an ordinary paragraph, which is how an agent
// reads a rule's description. Source without frontmatter is returned
// unchanged.
func blankFrontmatterDelimiters(source []byte) []byte {
	start := 0
	if bytes.HasPrefix(source, []byte("\xef\xbb\xbf")) {
		start = len("\xef\xbb\xbf")
	}
	firstEnd := lineEnd(source, start)
	if !isFrontmatterDelimiter(source[start:firstEnd], false) {
		return source
	}
	for pos := nextLine(source, firstEnd); pos < len(source); pos = nextLine(source, pos) {
		end := lineEnd(source, pos)
		if isFrontmatterDelimiter(source[pos:end], true) {
			out := bytes.Clone(source)
			blank(out[start:firstEnd])
			blank(out[pos:end])
			return out
		}
		pos = end
	}
	return source
}

// lineEnd returns the offset of the newline ending the line at pos, or
// len(b) for the last line.
func lineEnd(b []byte, pos int) int {
	if i := bytes.IndexByte(b[pos:], '\n'); i >= 0 {
		return pos + i
	}
	return len(b)
}

// nextLine returns the offset just past the newline at end.
func nextLine(b []byte, end int) int {
	if end < len(b) {
		return end + 1
	}
	return len(b)
}

func isFrontmatterDelimiter(line []byte, closing bool) bool {
	line = bytes.TrimRight(line, " \t\r")
	return string(line) == "---" || (closing && string(line) == "...")
}

func blank(b []byte) {
	for i, c := range b {
		if c != '\r' {
			b[i] = ' '
		}
	}
}

func walkNode(n ast.Node, source []byte, sections *[]MarkdownSection, fullSource []byte) {
	switch node := n.(type) {
	case *ast.Heading:
		*sections = append(*sections, MarkdownSection{
			Type:  SectionHeading,
			Text:  extractText(node, source),
			Line:  lineFromNode(node, fullSource),
			Level: node.Level,
		})
	case *ast.Paragraph:
		text := extractText(node, source)
		line := lineFromNode(node, fullSource)
		if isHTMLComment(text) {
			*sections = append(*sections, MarkdownSection{
				Type: SectionHTMLComment,
				Text: text,
				Line: line,
			})
		} else {
			*sections = append(*sections, MarkdownSection{
				Type: SectionParagraph,
				Text: text,
				Line: line,
			})
		}
	case *ast.FencedCodeBlock:
		lang := ""
		if node.Language(source) != nil {
			lang = string(node.Language(source))
		}
		*sections = append(*sections, MarkdownSection{
			Type:     SectionCodeBlock,
			Text:     extractCodeBlockText(node, source),
			Line:     lineFromNode(node, fullSource),
			Language: lang,
		})
	case *ast.HTMLBlock:
		text := extractHTMLBlockText(node, source)
		if isHTMLComment(text) {
			*sections = append(*sections, MarkdownSection{
				Type: SectionHTMLComment,
				Text: text,
				Line: lineFromNode(node, fullSource),
			})
		} else {
			// Non-comment HTML blocks (e.g. <HARD-GATE>, <Bad>, <Good>)
			// are treated as paragraphs, not hidden instructions.
			*sections = append(*sections, MarkdownSection{
				Type: SectionParagraph,
				Text: text,
				Line: lineFromNode(node, fullSource),
			})
		}
	case *ast.ListItem:
		*sections = append(*sections, MarkdownSection{
			Type: SectionListItem,
			Text: extractText(node, source),
			Line: lineFromNode(node, fullSource),
		})
	}

	for child := n.FirstChild(); child != nil; child = child.NextSibling() {
		if child == n {
			continue
		}
		walkNode(child, source, sections, fullSource)
	}
}

func extractText(n ast.Node, source []byte) string {
	var buf bytes.Buffer
	for child := n.FirstChild(); child != nil; child = child.NextSibling() {
		if t, ok := child.(*ast.Text); ok {
			buf.Write(t.Segment.Value(source))
			if t.SoftLineBreak() || t.HardLineBreak() {
				buf.WriteByte('\n')
			}
		} else {
			// recurse for inline elements
			buf.WriteString(extractText(child, source))
		}
	}
	return buf.String()
}

func extractCodeBlockText(n *ast.FencedCodeBlock, source []byte) string {
	var buf bytes.Buffer
	lines := n.Lines()
	for i := range lines.Len() {
		seg := lines.At(i)
		buf.Write(seg.Value(source))
	}
	return buf.String()
}

func extractHTMLBlockText(n *ast.HTMLBlock, source []byte) string {
	var buf bytes.Buffer
	lines := n.Lines()
	for i := range lines.Len() {
		seg := lines.At(i)
		buf.Write(seg.Value(source))
	}
	return buf.String()
}

func lineFromNode(n ast.Node, source []byte) int {
	// Get byte offset from the node's line segments
	var offset int
	if n.Lines().Len() > 0 {
		offset = n.Lines().At(0).Start
	} else {
		// For nodes without line segments (e.g. headings), try child text segments
		for child := n.FirstChild(); child != nil; child = child.NextSibling() {
			if t, ok := child.(*ast.Text); ok {
				offset = t.Segment.Start
				break
			}
		}
	}
	// Convert byte offset to 1-based line number
	line := 1
	for i := 0; i < offset && i < len(source); i++ {
		if source[i] == '\n' {
			line++
		}
	}
	return line
}

func isHTMLComment(text string) bool {
	return len(text) >= 7 && text[:4] == "<!--"
}

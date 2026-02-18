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
	Line     int // 1-based line number
	Language string // for code blocks
	Level    int    // for headings
}

// ParseMarkdown extracts structured sections from markdown content.
func ParseMarkdown(source []byte) []MarkdownSection {
	md := goldmark.New()
	reader := text.NewReader(source)
	doc := md.Parser().Parse(reader)

	var sections []MarkdownSection
	walkNode(doc, source, &sections, source)
	return sections
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

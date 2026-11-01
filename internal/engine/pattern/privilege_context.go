package pattern

import (
	"encoding/json"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/garagon/aguara/internal/scanner"
	"gopkg.in/yaml.v3"
)

const privilegeWordPattern = `(?i)\bsetuid\b|\bsetgid\b|\bcap_setuid\b`

var privilegeOperation = regexp.MustCompile(`(?i)\b(?:setuid|setgid|cap_setuid)\s*(?:[0-9=+]|root\b)|\bsetcap\b`)

type privilegeSpan struct{ start, end int }

type privilegePosition struct{ line, column, offset int }

// Scalar nodes arrive in source order. Reuse the column cursor so a compact
// JSON document does not rescan its entire line for each scalar's byte offset.
func (p *privilegePosition) locate(n *yaml.Node, content string, lines []int) (int, bool) {
	if n.Line < 1 || n.Line > len(lines) || n.Column < 1 || n.Line < p.line ||
		(n.Line == p.line && n.Column < p.column) {
		return 0, false
	}
	if n.Line != p.line {
		p.line, p.column, p.offset = n.Line, 1, lines[n.Line-1]
	}
	end := len(content)
	if n.Line < len(lines) {
		end = lines[n.Line] - 1
	}
	for p.column < n.Column && p.offset < end {
		_, size := utf8.DecodeRuneInString(content[p.offset:])
		p.offset += size
		p.column++
	}
	return p.offset, p.column == n.Column && p.offset < len(content)
}

// Only the built-in bare-word predicate receives this view. Command predicates,
// decoded payloads and custom patterns retain their original input. Unknown
// syntax falls back to the legacy detector, never to a clean scan.
func privilegeWordContent(target *scanner.Target, content string) string {
	ext := strings.ToLower(filepath.Ext(target.RelPath))
	if ext != ".json" && ext != ".yaml" && ext != ".yml" {
		return content
	}
	if len(content) > 2<<20 || string(target.SourceContent()) != content || strings.ContainsAny(content, "\ufeff\u0085\u2028\u2029") {
		return content
	}
	if ext == ".json" && !json.Valid([]byte(content)) {
		return content
	}
	lineStarts := []int{0}
	for i, c := range content {
		if c == '\r' && (i+1 == len(content) || content[i+1] != '\n') {
			return content
		}
		if c == '\n' {
			lineStarts = append(lineStarts, i+1)
		}
	}
	spans := make(map[*yaml.Node]privilegeSpan)
	var documents []*yaml.Node
	remaining := 10000
	commentsSafe := true
	var position privilegePosition
	var inspect func(*yaml.Node, int) bool
	inspect = func(n *yaml.Node, depth int) bool {
		remaining--
		if remaining < 0 || depth > 64 || n.Kind == yaml.AliasNode || n.Anchor != "" || n.Style&yaml.TaggedStyle != 0 {
			return false
		}
		if n.Kind == yaml.ScalarNode {
			span, ok := privilegeSpan{}, false
			if start, located := position.locate(n, content, lineStarts); located {
				span, ok = privilegeScalarSpan(n, content, start)
			}
			if ok {
				spans[n] = span
			}
			if !ok || strings.Contains(content[span.start:span.end], "\n") {
				commentsSafe = false
			}
		}
		if n.Kind == yaml.MappingNode {
			seen := make(map[string]bool)
			for i := 0; i < len(n.Content); i += 2 {
				key := n.Content[i]
				if key.Kind != yaml.ScalarNode || seen[key.Value] || key.Value == "<<" {
					return false
				}
				seen[key.Value] = true
			}
		}
		for _, child := range n.Content {
			if !inspect(child, depth+1) {
				return false
			}
		}
		return true
	}
	decoder := yaml.NewDecoder(strings.NewReader(content))
	for {
		var doc yaml.Node
		err := decoder.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil || !inspect(&doc, 0) {
			return content
		}
		documents = append(documents, &doc)
	}
	var inert []privilegeSpan
	mark := func(n *yaml.Node) {
		if span, ok := spans[n]; ok {
			inert = append(inert, span)
		}
	}
	var walk func(*yaml.Node, string)
	walk = func(n *yaml.Node, parentKey string) {
		if n.Kind == yaml.MappingNode {
			for i := 0; i < len(n.Content); i += 2 {
				key, value := n.Content[i], n.Content[i+1]
				if key.Tag != "!!str" {
					continue
				}
				if parentKey == "capabilities" && key.Value == "drop" && value.Kind == yaml.SequenceNode {
					for _, item := range value.Content {
						if item.Kind == yaml.ScalarNode && item.Tag == "!!str" && privilegeCapability(item.Value) {
							mark(item)
						}
					}
				}
				if (key.Value == "setuid" || key.Value == "setgid") && value.Tag == "!!bool" && value.Value == "false" {
					mark(key)
				}
				if key.Value == "description" && value.Kind == yaml.ScalarNode && value.Tag == "!!str" &&
					!strings.ContainsAny(value.Value, "()$`|;&<>\\\n") && !privilegeOperation.MatchString(value.Value) {
					mark(value)
				}
				walk(value, key.Value)
			}
			return
		}
		for _, child := range n.Content {
			walk(child, "")
		}
	}
	for _, doc := range documents {
		walk(doc, "")
	}
	// Full-line comments only. Multiline scalar syntax disables this shortcut:
	// a leading '#' inside a literal or quoted value is data, not a YAML comment.
	if commentsSafe && ext != ".json" {
		for i, start := range lineStarts {
			end := len(content)
			if i+1 < len(lineStarts) {
				end = lineStarts[i+1]
			}
			if strings.HasPrefix(strings.TrimSpace(content[start:end]), "#") {
				inert = append(inert, privilegeSpan{start, end})
			}
		}
	}
	if len(inert) == 0 {
		return content
	}
	masked := []byte(content)
	for _, span := range inert {
		for i := span.start; i < span.end; i++ {
			if masked[i] != '\n' && masked[i] != '\r' {
				masked[i] = ' '
			}
		}
	}
	return string(masked)
}

func privilegeCapability(value string) bool {
	switch strings.ToUpper(value) {
	case "SETUID", "SETGID", "CAP_SETUID", "CAP_SETGID":
		return true
	}
	return false
}

// Resolve only simple scalar spans, without guessing folded/literal extents.
func privilegeScalarSpan(n *yaml.Node, content string, start int) (privilegeSpan, bool) {
	if n.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		return privilegeSpan{}, false
	}
	if start >= len(content) {
		return privilegeSpan{}, false
	}
	if n.Style&(yaml.SingleQuotedStyle|yaml.DoubleQuotedStyle) != 0 {
		quote := content[start]
		if (n.Style&yaml.SingleQuotedStyle != 0 && quote != '\'') ||
			(n.Style&yaml.DoubleQuotedStyle != 0 && quote != '"') {
			return privilegeSpan{}, false
		}
		for end := start + 1; end < len(content); end++ {
			if quote == '"' && content[end] == '\\' {
				end++
				continue
			}
			if content[end] == quote {
				if quote == '\'' && end+1 < len(content) && content[end+1] == quote {
					end++
					continue
				}
				return privilegeSpan{start, end + 1}, true
			}
		}
		return privilegeSpan{}, false
	}
	if strings.HasPrefix(content[start:], n.Value) {
		return privilegeSpan{start, start + len(n.Value)}, true
	}
	return privilegeSpan{}, false
}

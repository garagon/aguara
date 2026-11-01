// Package kubeconfig recognizes bounded Kubernetes configuration evidence.
// It neither resolves templates nor evaluates runtime privileges or policy.
package kubeconfig

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// MaxBytes is the shared parsing and suppression budget.
const MaxBytes = 2 << 20

// Span identifies an original source scalar, including any quotes.
type Span struct{ Start, End int }

// Document contains a validated stream and source positions. Partial scalar
// coverage is useful to the legacy inert-value matcher, but cannot transfer
// Kubernetes detection ownership.
type Document struct {
	Nodes         []*yaml.Node
	Spans         map[*yaml.Node]Span
	LineStarts    []int
	CommentsSafe  bool
	completeSpans bool
}

// Parse returns nil for unsupported syntax, never a partially parsed stream.
// The caller must retain legacy matching in that case. Only cancellation is an
// error; this bounded recognizer is not a configuration-validity certification.
func Parse(ctx context.Context, content, ext string) (*Document, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if ext != ".json" && ext != ".yaml" && ext != ".yml" {
		return nil, nil
	}
	if len(content) > MaxBytes || strings.ContainsAny(content, "\ufeff\u0085\u2028\u2029") ||
		(ext == ".json" && !json.Valid([]byte(content))) {
		return nil, nil
	}
	d := &Document{Spans: make(map[*yaml.Node]Span), LineStarts: []int{0}, CommentsSafe: true, completeSpans: true}
	for i, c := range content {
		if c == '\r' && (i+1 == len(content) || content[i+1] != '\n') {
			return nil, nil
		}
		if c == '\n' {
			d.LineStarts = append(d.LineStarts, i+1)
		}
	}
	remaining := 10000
	var cursor position
	var inspect func(*yaml.Node, int) bool
	inspect = func(n *yaml.Node, depth int) bool {
		remaining--
		if ctx.Err() != nil || remaining < 0 || depth > 64 || n.Kind == yaml.AliasNode || n.Anchor != "" || n.Style&yaml.TaggedStyle != 0 {
			return false
		}
		if n.Kind == yaml.ScalarNode {
			span, ok := Span{}, false
			if start, located := cursor.locate(n, content, d.LineStarts); located {
				span, ok = scalarSpan(n, content, start)
			}
			if ok {
				d.Spans[n] = span
			} else {
				d.completeSpans = false
			}
			if !ok || strings.Contains(content[span.Start:span.End], "\n") {
				d.CommentsSafe = false
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
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var node yaml.Node
		err := decoder.Decode(&node)
		if err == io.EOF {
			return d, nil
		}
		if err != nil || !inspect(&node, 0) {
			return nil, ctx.Err()
		}
		d.Nodes = append(d.Nodes, &node)
	}
}

type position struct{ line, column, offset int }

// Scalar nodes arrive in source order; keep compact JSON offset lookup linear.
func (p *position) locate(n *yaml.Node, content string, lines []int) (int, bool) {
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

func scalarSpan(n *yaml.Node, content string, start int) (Span, bool) {
	if n.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 || start >= len(content) {
		return Span{}, false
	}
	if n.Style&(yaml.SingleQuotedStyle|yaml.DoubleQuotedStyle) != 0 {
		quote := content[start]
		if (n.Style&yaml.SingleQuotedStyle != 0 && quote != '\'') ||
			(n.Style&yaml.DoubleQuotedStyle != 0 && quote != '"') {
			return Span{}, false
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
				return Span{start, end + 1}, true
			}
		}
		return Span{}, false
	}
	if strings.HasPrefix(content[start:], n.Value) {
		return Span{start, start + len(n.Value)}, true
	}
	return Span{}, false
}

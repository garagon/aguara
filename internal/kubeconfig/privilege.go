package kubeconfig

import (
	"context"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var privilegeOperation = regexp.MustCompile(`(?i)\b(?:setuid|setgid|cap_setuid)\s*(?:[0-9=+]|root\b)|\bsetcap\b`)

// PrivilegeAnalysis retains only read-only source spans and classification, not
// the YAML tree or source text. Both privilege consumers share this evidence.
type PrivilegeAnalysis struct {
	MaskedSpans []Span
	Identity    Classification
}

// AnalyzePrivileges preserves the legacy inert-value masking and adds only
// structurally owned capability spans. Unsupported parses return nil.
func AnalyzePrivileges(ctx context.Context, content, ext string) (*PrivilegeAnalysis, error) {
	doc, err := Parse(ctx, content, ext)
	if err != nil || doc == nil {
		return nil, err
	}
	result := &PrivilegeAnalysis{Identity: doc.IdentityCapabilities()}
	mark := func(n *yaml.Node) {
		if span, ok := doc.Spans[n]; ok {
			result.MaskedSpans = append(result.MaskedSpans, span)
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
	for _, node := range doc.Nodes {
		walk(node, "")
	}
	for _, grant := range result.Identity.Grants {
		result.MaskedSpans = append(result.MaskedSpans, grant.Spans...)
	}
	// A '#' in a multiline scalar is data, not necessarily a YAML comment.
	if doc.CommentsSafe && ext != ".json" {
		for i, start := range doc.LineStarts {
			end := len(content)
			if i+1 < len(doc.LineStarts) {
				end = doc.LineStarts[i+1]
			}
			if strings.HasPrefix(strings.TrimSpace(content[start:end]), "#") {
				result.MaskedSpans = append(result.MaskedSpans, Span{Start: start, End: end})
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func privilegeCapability(value string) bool {
	switch strings.ToUpper(value) {
	case "SETUID", "SETGID", "CAP_SETUID", "CAP_SETGID":
		return true
	}
	return false
}

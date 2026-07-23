// Package skillpolicy analyzes the security posture declared by agent-skill
// metadata. It parses only the YAML frontmatter of SKILL.md; examples and
// prose in the markdown body cannot become policy findings.
package skillpolicy

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"

	"github.com/garagon/aguara/internal/rulemeta"
	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
	"gopkg.in/yaml.v3"
)

const (
	RuleWildcardTools = "AGENT_SKILL_WILDCARD_TOOLS_001"
	AnalyzerName      = rulemeta.AnalyzerSkillPolicy

	maxFrontmatterBytes = 64 << 10
)

type Analyzer struct{}

func New() *Analyzer {
	return &Analyzer{}
}

func (a *Analyzer) Name() string {
	return AnalyzerName
}

func (a *Analyzer) Analyze(ctx context.Context, target *scanner.Target) ([]scanner.Finding, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if !strings.EqualFold(filepath.Base(target.RelPath), "SKILL.md") {
		return nil, nil
	}

	root := parseFrontmatter(target.Content)
	if root == nil {
		return nil, nil
	}
	value := lastTopLevelValue(root, "allowed-tools")
	wildcard := wholeWildcardNode(value)
	if wildcard == nil {
		return nil, nil
	}

	meta := ruleInfo[RuleWildcardTools]
	// yaml.Node line numbers are relative to the frontmatter payload, which
	// starts one line after the opening delimiter.
	line := wildcard.Line + 1
	lines := target.Lines()
	matched := ""
	if line > 0 && line <= len(lines) {
		matched = strings.TrimSpace(lines[line-1])
	}
	return []scanner.Finding{{
		RuleID:      meta.ID,
		RuleName:    meta.Name,
		Severity:    meta.SeverityLevel(),
		Category:    meta.Category,
		Description: meta.Description,
		FilePath:    target.RelPath,
		Line:        line,
		MatchedText: matched,
		Context:     types.ExtractContext(lines, line, 2, 2),
		Confidence:  0.98,
		Remediation: meta.Remediation,
		Analyzer:    AnalyzerName,
	}}, nil
}

func parseFrontmatter(content []byte) *yaml.Node {
	content = bytes.TrimPrefix(content, []byte{0xef, 0xbb, 0xbf})
	firstEnd := bytes.IndexByte(content, '\n')
	if firstEnd < 0 || strings.TrimSpace(string(content[:firstEnd])) != "---" {
		return nil
	}

	headerStart := firstEnd + 1
	if headerStart >= len(content) {
		return nil
	}
	searchEnd := len(content)
	if searchEnd-headerStart > maxFrontmatterBytes {
		searchEnd = headerStart + maxFrontmatterBytes
	}
	headerEnd := -1
	for offset := headerStart; offset < searchEnd; {
		next := bytes.IndexByte(content[offset:searchEnd], '\n')
		lineEnd := searchEnd
		if next >= 0 {
			lineEnd = offset + next
		}
		line := strings.TrimSpace(strings.TrimSuffix(string(content[offset:lineEnd]), "\r"))
		if line == "---" || line == "..." {
			headerEnd = offset
			break
		}
		if next < 0 {
			break
		}
		offset = lineEnd + 1
	}
	if headerEnd < 0 {
		return nil
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(content[headerStart:headerEnd], &doc); err != nil {
		return nil
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil
	}
	return doc.Content[0]
}

func lastTopLevelValue(root *yaml.Node, key string) *yaml.Node {
	var value *yaml.Node
	for i := 0; i+1 < len(root.Content); i += 2 {
		keyNode := root.Content[i]
		if keyNode.Kind == yaml.ScalarNode && keyNode.Value == key {
			value = root.Content[i+1]
		}
	}
	return value
}

func wholeWildcardNode(value *yaml.Node) *yaml.Node {
	if value == nil {
		return nil
	}
	if value.Kind == yaml.ScalarNode && value.Tag == "!!str" && strings.TrimSpace(value.Value) == "*" {
		return value
	}
	return nil
}

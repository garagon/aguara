// Package mcpcapability distinguishes broad grants from capability removal
// using configuration structure rather than proximity to a dangerous word.
package mcpcapability

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/garagon/aguara/internal/engine/pattern"
	"github.com/garagon/aguara/internal/rulemeta"
	"github.com/garagon/aguara/internal/rules"
	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
	"gopkg.in/yaml.v3"
)

const (
	RuleCapabilityEscalation = "MCP_009"
	maxConfigBytes           = 2 << 20
	maxNodes                 = 100000
)

var (
	configKey  = regexp.MustCompile(`(?i)["']?(capabilities|permissions)["']?\s*[:=]`)
	request    = regexp.MustCompile(`(?i)request\w*\s+(unrestricted|admin|root|superuser)\s+(capabilities|permissions|access)`)
	assignment = regexp.MustCompile(`(?im)^([ \t]*(?:"(?:capabilities|permissions)"|'(?:capabilities|permissions)'|capabilities|permissions)[ \t]*)=`)
)

type Analyzer struct {
	disabled bool
	severity types.Severity
}

func New() *Analyzer { return NewWithOverride(rules.RuleOverride{}) }

// NewWithOverride preserves the severity/disable contract of the former
// pattern rule. Other analyzer rules retain their existing override semantics.
func NewWithOverride(override rules.RuleOverride) *Analyzer {
	severity := types.SeverityHigh
	if s, err := types.ParseSeverity(override.Severity); override.Severity != "" && err == nil {
		severity = s
	}
	return &Analyzer{disabled: override.Disabled, severity: severity}
}
func (a *Analyzer) Name() string { return rulemeta.AnalyzerMCPCapability }

func (a *Analyzer) Analyze(ctx context.Context, target *scanner.Target) ([]scanner.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if a.disabled {
		return nil, nil
	}
	ext := strings.ToLower(filepath.Ext(target.RelPath))
	text := ext == ".md" || ext == ".txt"
	if !text && ext != ".json" && ext != ".yaml" && ext != ".yml" {
		return nil, nil
	}
	source := target.SourceContent()
	hasConfig := configKey.Match(source)
	if !hasConfig && (!text || !request.Match(target.Content)) {
		return nil, nil
	}
	if hasConfig && len(source) > maxConfigBytes {
		return nil, fmt.Errorf("MCP capability analysis exceeds %d-byte input limit", maxConfigBytes)
	}
	if ext == ".json" && !json.Valid(source) {
		return nil, nil
	}
	lines := strings.Split(string(source), "\n")
	var blocks []bool
	if ext == ".md" {
		blocks = pattern.BuildCodeBlockMap(lines)
	}
	var findings []scanner.Finding
	seen := make(map[int]bool)
	emit := func(line, column int, evidence string) {
		if seen[line] {
			return
		}
		seen[line] = true
		meta := RuleMetadata()[0]
		severity := a.severity
		inBlock := line > 0 && line <= len(blocks) && blocks[line-1]
		if inBlock {
			severity = types.DowngradeSeverity(severity)
		}
		findings = append(findings, scanner.Finding{
			RuleID: meta.ID, RuleName: meta.Name, Severity: severity,
			Category: meta.Category, Description: meta.Description,
			FilePath: target.RelPath, Line: line, Column: column,
			MatchedText: evidence, Confidence: 0.95, InCodeBlock: inBlock,
			Remediation: meta.Remediation, Analyzer: a.Name(),
		})
	}
	remaining := maxNodes
	parse := func(content []byte, offset int) error {
		if !configKey.Match(content) {
			return nil
		}
		// Equals assignments are a text-snippet convention, not JSON/YAML.
		if text {
			content = assignment.ReplaceAll(content, []byte("${1}:"))
		}
		decoder := yaml.NewDecoder(bytes.NewReader(content))
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			var doc yaml.Node
			if err := decoder.Decode(&doc); err != nil {
				if err == io.EOF {
					return nil
				}
				// Malformed syntax is not evidence of a broad grant.
				return nil
			}
			stack := []*yaml.Node{&doc}
			for len(stack) > 0 {
				if err := ctx.Err(); err != nil {
					return err
				}
				remaining--
				if remaining < 0 {
					return fmt.Errorf("MCP capability analysis exceeds node limit")
				}
				node := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				switch node.Kind {
				case yaml.DocumentNode, yaml.SequenceNode:
					for i := len(node.Content) - 1; i >= 0; i-- {
						stack = append(stack, node.Content[i])
					}
				case yaml.MappingNode:
					// Duplicate keys have no portable effective value. Do not
					// choose a winner and invent a grant for an ambiguous field.
					keys := make(map[string]int)
					for i := 0; i+1 < len(node.Content); i += 2 {
						keys[node.Content[i].Value]++
					}
					for i := 0; i+1 < len(node.Content); i += 2 {
						key, value := node.Content[i], node.Content[i+1]
						if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || keys[key.Value] != 1 {
							continue
						}
						if strings.EqualFold(key.Value, "capabilities") || strings.EqualFold(key.Value, "permissions") {
							for _, grant := range broadGrants(value) {
								emit(grant.Line+offset, grant.Column, key.Value+": "+grant.Value)
							}
							// In particular, never reinterpret drop/deny data as
							// a fresh capability declaration.
							continue
						}
						stack = append(stack, value)
					}
					// Aliases are not expanded: no cycles, merge precedence guesses
					// or exponential work on attacker-controlled YAML graphs.
				}
			}
		}
	}
	if text {
		// Prose requests remain supported. Configuration data in JSON/YAML
		// strings and comments is not scanned as natural-language instructions.
		// Keep the normalized text view for prose, but never for config parsing.
		prose := target.Content
		line, lineStart, previous := 1, 0, 0
		for _, match := range request.FindAllIndex(prose, -1) {
			if err := ctx.Err(); err != nil {
				return findings, err
			}
			between := prose[previous:match[0]]
			line += bytes.Count(between, []byte("\n"))
			if newline := bytes.LastIndexByte(between, '\n'); newline >= 0 {
				lineStart = previous + newline + 1
			}
			emit(line, match[0]-lineStart+1, string(prose[match[0]:match[1]]))
			previous = match[0]
		}
	}
	if !hasConfig {
		return findings, nil
	}
	if len(blocks) == 0 {
		if err := parse(source, 0); err != nil {
			return findings, err
		}
	} else {
		// Parse fenced examples independently, preserving their original lines
		// and the pattern matcher's existing code-block severity downgrade.
		start := 0
		for i, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), "```") {
				if err := parse([]byte(strings.Join(lines[start:i], "\n")), start); err != nil {
					return findings, err
				}
				start = i + 1
			}
		}
		if err := parse([]byte(strings.Join(lines[start:], "\n")), start); err != nil {
			return findings, err
		}
	}
	return findings, nil
}

func broadGrants(value *yaml.Node) []*yaml.Node {
	if value.Kind != yaml.MappingNode {
		return broadValues(value)
	}
	var out []*yaml.Node
	keys := make(map[string]int)
	for i := 0; i+1 < len(value.Content); i += 2 {
		keys[strings.ToLower(value.Content[i].Value)]++
	}
	for i := 0; i+1 < len(value.Content); i += 2 {
		key := value.Content[i]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			continue
		}
		name := strings.ToLower(key.Value)
		if keys[name] != 1 {
			continue
		}
		switch name {
		case "add", "allow", "grant":
			out = append(out, broadValues(value.Content[i+1])...)
		}
	}
	return out
}

func broadValues(value *yaml.Node) []*yaml.Node {
	values := []*yaml.Node{value}
	if value.Kind == yaml.SequenceNode {
		values = value.Content
	}
	var out []*yaml.Node
	for _, v := range values {
		if v.Kind != yaml.ScalarNode || v.Tag != "!!str" {
			continue
		}
		switch strings.ToLower(v.Value) {
		case "all", "admin", "unrestricted", "root", "superuser", "full_access", "god_mode":
			out = append(out, v)
		}
	}
	return out
}

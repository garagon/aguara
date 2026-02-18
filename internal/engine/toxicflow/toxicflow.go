// Package toxicflow detects dangerous capability combinations within a single
// skill or MCP server. When a file exhibits both "reads private data" and
// "writes to public channels", for example, it flags the toxic flow as a
// potential exfiltration vector.
package toxicflow

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
)

// capability represents a classified capability label.
type capability string

const (
	readsPrivateData   capability = "reads_private_data"
	writesPublicOutput capability = "writes_public_output"
	executesCode       capability = "executes_code"
	destructive        capability = "destructive"
)

// capPattern maps a capability to its detection patterns.
type capPattern struct {
	cap      capability
	patterns []*regexp.Regexp
}

var classifiers = []capPattern{
	{
		cap: readsPrivateData,
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(read|access|open|load|cat)\s+.{0,30}(credentials?|secrets?|private.key|\.ssh|\.env|\.aws|\.gnupg)`),
			regexp.MustCompile(`(?i)/etc/(passwd|shadow)`),
			regexp.MustCompile(`(?i)~/?\.ssh/(id_rsa|id_ed25519|authorized_keys)`),
		},
	},
	{
		cap: writesPublicOutput,
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(send|post|forward|share)\s+.{0,30}(to|via)\s+.{0,20}(slack|discord|email|webhook|channel)`),
			regexp.MustCompile(`(?i)hooks\.slack\.com/services/`),
			regexp.MustCompile(`(?i)(discord|discordapp)\.com/api/webhooks/`),
			regexp.MustCompile(`(?i)(gmail|smtp|imap)\s+(send|compose|forward)`),
		},
	},
	{
		cap: executesCode,
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(eval|exec)\s*\(`),
			regexp.MustCompile(`(?i)(subprocess|child_process)\.(call|run|exec|spawn)\s*\(`),
			regexp.MustCompile(`(?i)os\.(system|popen)\s*\(`),
			regexp.MustCompile(`(?i)shell\s*=\s*(True|true)\b`),
		},
	},
	{
		cap: destructive,
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)\brm\s+-rf?\s+/`),
			regexp.MustCompile(`(?i)DROP\s+(TABLE|DATABASE)\b`),
			regexp.MustCompile(`(?i)delete\s+.{0,20}(all|entire|every|database|table|collection)\b`),
			regexp.MustCompile(`(?i)(format|wipe)\s+.{0,20}(disk|drive|partition)\b`),
		},
	},
}

// toxicPair defines a dangerous combination of capabilities.
type toxicPair struct {
	a, b        capability
	ruleID      string
	name        string
	description string
}

var toxicPairs = []toxicPair{
	{
		a:           readsPrivateData,
		b:           writesPublicOutput,
		ruleID:      "TOXIC_001",
		name:        "Private data read with public output",
		description: "Skill can read private data (credentials, SSH keys, env vars) AND write to public channels (Slack, Discord, email). This combination enables data exfiltration.",
	},
	{
		a:           readsPrivateData,
		b:           executesCode,
		ruleID:      "TOXIC_002",
		name:        "Private data read with code execution",
		description: "Skill can read private data AND execute arbitrary code. This combination enables credential theft via dynamic code.",
	},
	{
		a:           destructive,
		b:           executesCode,
		ruleID:      "TOXIC_003",
		name:        "Destructive actions with code execution",
		description: "Skill has destructive capabilities AND can execute arbitrary code. This combination enables ransomware-like attacks.",
	},
}

// Analyzer implements the scanner.Analyzer interface for toxic flow detection.
type Analyzer struct{}

// New creates a new toxic flow Analyzer.
func New() *Analyzer {
	return &Analyzer{}
}

// Name returns the analyzer name.
func (a *Analyzer) Name() string { return "toxicflow" }

// Analyze scans the target for capability combinations that indicate
// dangerous data flows within a single skill.
func (a *Analyzer) Analyze(_ context.Context, target *scanner.Target) ([]types.Finding, error) {
	if len(target.Content) == 0 {
		return nil, nil
	}

	content := string(target.Content)

	// Classify capabilities present in this file
	detected := make(map[capability]capMatch)
	for _, cp := range classifiers {
		for _, pat := range cp.patterns {
			loc := pat.FindStringIndex(content)
			if loc != nil {
				detected[cp.cap] = capMatch{
					text: content[loc[0]:loc[1]],
					line: strings.Count(content[:loc[0]], "\n") + 1,
				}
				break // one match per capability is enough
			}
		}
	}

	// Check for toxic combinations
	var findings []types.Finding
	for _, tp := range toxicPairs {
		matchA, okA := detected[tp.a]
		matchB, okB := detected[tp.b]
		if !okA || !okB {
			continue
		}

		// Use the line of the first matching capability for the finding location
		line := matchA.line
		matchedText := fmt.Sprintf("[%s] %s + [%s] %s", tp.a, matchA.text, tp.b, matchB.text)

		findings = append(findings, types.Finding{
			RuleID:      tp.ruleID,
			RuleName:    tp.name,
			Severity:    types.SeverityHigh,
			Category:    "toxic-flow",
			Description: tp.description,
			FilePath:    target.Path,
			Line:        line,
			MatchedText: matchedText,
			Analyzer:    "toxicflow",
		})
	}

	return findings, nil
}

type capMatch struct {
	text string
	line int
}

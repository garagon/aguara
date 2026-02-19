package output

import (
	"encoding/json"
	"io"

	"github.com/garagon/aguara/internal/scanner"
)

// ToolVersion is the aguara version reported in SARIF output.
var ToolVersion = "dev"

// SARIFFormatter outputs findings in SARIF 2.1.0 format for GitHub Code Scanning.
type SARIFFormatter struct{}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool      `json:"tool"`
	Results    []sarifResult  `json:"results"`
	Properties map[string]any `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	ShortDescription sarifMessage        `json:"shortDescription"`
	DefaultConfig    sarifDefaultConfig  `json:"defaultConfiguration"`
	Properties       sarifRuleProperties `json:"properties"`
}

type sarifDefaultConfig struct {
	Level string `json:"level"`
}

type sarifRuleProperties struct {
	Tags []string `json:"tags,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	RuleIndex  int             `json:"ruleIndex"`
	Level      string          `json:"level"`
	Message    sarifMessage    `json:"message"`
	Locations  []sarifLocation `json:"locations"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

func (f *SARIFFormatter) Format(w io.Writer, result *scanner.ScanResult) error {
	// Collect unique rules in order
	ruleIndex := map[string]int{}
	var rules []sarifRule
	for _, finding := range result.Findings {
		if _, ok := ruleIndex[finding.RuleID]; !ok {
			ruleIndex[finding.RuleID] = len(rules)
			rules = append(rules, sarifRule{
				ID:               finding.RuleID,
				Name:             finding.RuleName,
				ShortDescription: sarifMessage{Text: finding.RuleName},
				DefaultConfig:    sarifDefaultConfig{Level: severityToLevel(finding.Severity)},
				Properties:       sarifRuleProperties{Tags: []string{finding.Category}},
			})
		}
	}

	// Build results
	var results []sarifResult
	for _, finding := range result.Findings {
		line := max(finding.Line, 1)
		col := max(finding.Column, 1)
		r := sarifResult{
			RuleID:    finding.RuleID,
			RuleIndex: ruleIndex[finding.RuleID],
			Level:     severityToLevel(finding.Severity),
			Message:   sarifMessage{Text: finding.RuleName + ": " + finding.MatchedText},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: finding.FilePath},
						Region:           sarifRegion{StartLine: line, StartColumn: col},
					},
				},
			},
		}
		if finding.InCodeBlock {
			r.Properties = map[string]any{"in_code_block": true}
		}
		results = append(results, r)
	}

	log := sarifLog{
		Schema:  "https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "aguara",
						Version:        ToolVersion,
						InformationURI: "https://github.com/garagon/aguara",
						Rules:          rules,
					},
				},
				Results:    results,
				Properties: map[string]any{"duration_ms": result.Duration.Milliseconds()},
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func severityToLevel(sev scanner.Severity) string {
	switch sev {
	case scanner.SeverityCritical:
		return "error"
	case scanner.SeverityHigh:
		return "warning"
	case scanner.SeverityMedium, scanner.SeverityLow:
		return "note"
	case scanner.SeverityInfo:
		return "none"
	default:
		return "none"
	}
}

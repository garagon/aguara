// Package kubepolicy reports explicit Kubernetes capability requests as posture,
// not as evidence of executed privilege escalation.
package kubepolicy

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"

	"github.com/garagon/aguara/internal/kubeconfig"
	"github.com/garagon/aguara/internal/rulemeta"
	"github.com/garagon/aguara/internal/scanner"
)

const RuleIdentityCapabilities = "K8S_IDENTITY_CAPABILITIES_001"

type Analyzer struct{}

func New() *Analyzer { return &Analyzer{} }

func (a *Analyzer) Name() string { return rulemeta.AnalyzerKubePolicy }

func (a *Analyzer) Analyze(ctx context.Context, target *scanner.Target) ([]scanner.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ext := strings.ToLower(filepath.Ext(target.RelPath))
	if ext != ".json" && ext != ".yaml" && ext != ".yml" {
		return nil, nil
	}
	source := target.SourceContent()
	// Canonical identity names must occur literally or through a YAML/JSON
	// escape. Keep escaped keys/values eligible without parsing ordinary YAML.
	if !bytes.Contains(source, []byte("SETUID")) && !bytes.Contains(source, []byte("SETGID")) && bytes.IndexByte(source, '\\') < 0 {
		return nil, nil
	}
	if len(source) > kubeconfig.MaxBytes {
		return nil, nil
	}
	analysis, err := target.PrivilegeAnalysis(ctx)
	if err != nil {
		return nil, err
	}
	if analysis == nil {
		return nil, nil
	}
	meta := RuleMetadata()[0]
	var findings []scanner.Finding
	for _, grant := range analysis.Identity.Grants {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		findings = append(findings, scanner.Finding{
			RuleID: meta.ID, RuleName: meta.Name, Severity: meta.SeverityLevel(),
			Category: meta.Category, Description: meta.Description, Remediation: meta.Remediation,
			FilePath: target.RelPath, Line: grant.Line, Column: grant.Column,
			MatchedText: grant.Path + ".securityContext.capabilities.add: " + strings.Join(grant.Capabilities, ", "),
			Confidence:  0.95, DecisionImpact: rulemeta.DecisionImpactContext, Analyzer: a.Name(),
		})
	}
	return findings, nil
}

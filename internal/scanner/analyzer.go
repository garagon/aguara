// Package scanner orchestrates file discovery, target classification,
// and multi-analyzer execution for security scanning of AI agent skills.
package scanner

import "context"

// Analyzer is the interface that all analysis engines must implement.
type Analyzer interface {
	Name() string
	Analyze(ctx context.Context, target *Target) ([]Finding, error)
}

package scanner

// This package re-exports types from internal/types for convenience.
// The canonical types live in internal/types to avoid import cycles.

import "github.com/garagon/aguara/internal/types"

type (
	Severity    = types.Severity
	ContextLine = types.ContextLine
	Finding     = types.Finding
	ScanResult  = types.ScanResult
)

const (
	SeverityInfo     = types.SeverityInfo
	SeverityLow      = types.SeverityLow
	SeverityMedium   = types.SeverityMedium
	SeverityHigh     = types.SeverityHigh
	SeverityCritical = types.SeverityCritical
)

var ParseSeverity = types.ParseSeverity

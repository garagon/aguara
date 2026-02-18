package meta

import (
	"fmt"

	"github.com/garagon/aguara/internal/types"
)

// Deduplicate removes duplicate findings by (FilePath, RuleID, Line) composite key,
// keeping the highest severity instance.
func Deduplicate(findings []types.Finding) []types.Finding {
	best := make(map[string]types.Finding)
	for _, f := range findings {
		k := fmt.Sprintf("%s:%s:%d", f.FilePath, f.RuleID, f.Line)
		if existing, ok := best[k]; ok {
			if f.Severity > existing.Severity {
				best[k] = f
			}
		} else {
			best[k] = f
		}
	}

	result := make([]types.Finding, 0, len(best))
	for _, f := range best {
		result = append(result, f)
	}
	return result
}

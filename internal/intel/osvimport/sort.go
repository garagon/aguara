package osvimport

import (
	"sort"

	"github.com/garagon/aguara/internal/intel"
)

// SortRecords sorts a record slice in place by (ecosystem, name, ID).
// Exposed so the generator (tools/update-intel) and the measurement
// tool (tools/measure-intel) emit records in one canonical order,
// keeping regeneration of the embedded snapshot deterministic.
func SortRecords(records []intel.Record) {
	sort.SliceStable(records, func(i, j int) bool {
		a, b := records[i], records[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.ID < b.ID
	})
}

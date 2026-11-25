package rulecatalog

import (
	"sync"

	"github.com/garagon/aguara/internal/engine"
	"github.com/garagon/aguara/internal/rules"
	"github.com/garagon/aguara/internal/rules/builtin"
)

var (
	builtinIDsOnce sync.Once
	builtinIDs     map[string]bool
)

// BuiltinIDs returns the IDs of the rules that ship with Aguara: the
// embedded YAML rules and every analyzer-emitted rule. Custom rules can
// never reuse these IDs. The map is shared; callers must not modify it.
func BuiltinIDs() map[string]bool {
	builtinIDsOnce.Do(func() {
		ids := map[string]bool{}
		// The embedded rules are tested to load; on the impossible error the
		// set holds the analyzer rules only.
		if raws, err := rules.LoadFromFS(builtin.FS()); err == nil {
			for _, raw := range raws {
				ids[raw.ID] = true
			}
		}
		for _, meta := range engine.RuleMetadata() {
			ids[meta.ID] = true
		}
		builtinIDs = ids
	})
	return builtinIDs
}

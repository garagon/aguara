package packagecheck

import (
	"encoding/json"
	"sort"

	"github.com/garagon/aguara/internal/jsonfields"
)

func (p *packageLock) UnmarshalJSON(data []byte) error {
	var next packageLock
	var dependencies json.RawMessage
	err := jsonfields.Decode(data,
		jsonfields.Field{Name: "packages", To: &next.Packages},
		jsonfields.Field{Name: "dependencies", To: &dependencies})
	if err == nil && len(dependencies) > 0 {
		budget := maxManifestBytes
		entries := 0
		next.Dependencies, err = decodeLockDependencies(dependencies, 0, &budget, &entries)
	}
	if err == nil {
		*p = next
	}
	return err
}

func (p *plPackagesEntry) UnmarshalJSON(data []byte) error {
	var next plPackagesEntry
	err := jsonfields.Decode(data,
		jsonfields.Field{Name: "name", To: &next.Name},
		jsonfields.Field{Name: "version", To: &next.Version},
		jsonfields.Field{Name: "resolved", To: &next.Resolved},
		jsonfields.Field{Name: "link", To: &next.Link})
	if err == nil {
		*p = next
	}
	return err
}

// Resolving duplicate members through raw objects otherwise reparses each
// nested subtree. Bound cumulative subtree bytes, recursion depth and the
// entries decoded: a lockfileVersion 1 tree repeats a package at every path
// that installs it, so it may hold up to four times the entry limit, and
// the count stops the decoding instead of the refs check afterwards.
func decodeLockDependencies(data []byte, depth int, budget *int64, entries *int) (map[string]plDepEntry, error) {
	if depth >= 128 || int64(len(data)) > *budget {
		return nil, errBudget("package-lock dependency tree exceeds decoding budget")
	}
	*budget -= int64(len(data))
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}
	keys := make([]string, 0, len(raw))
	for key := range raw {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if *entries += len(raw); *entries > 4*maxLockfileEntries {
		return nil, errBudget("package-lock dependency tree exceeds decoding budget: more than %d nested entries", 4*maxLockfileEntries)
	}
	decoded := make(map[string]plDepEntry, len(raw))
	for _, key := range keys {
		var entry plDepEntry
		var children json.RawMessage
		if err := jsonfields.Decode(raw[key],
			jsonfields.Field{Name: "version", To: &entry.Version},
			jsonfields.Field{Name: "resolved", To: &entry.Resolved},
			jsonfields.Field{Name: "link", To: &entry.Link},
			jsonfields.Field{Name: "dependencies", To: &children}); err != nil {
			return nil, err
		}
		if len(children) > 0 {
			var err error
			entry.Dependencies, err = decodeLockDependencies(children, depth+1, budget, entries)
			if err != nil {
				return nil, err
			}
		}
		decoded[key] = entry
	}
	return decoded, nil
}

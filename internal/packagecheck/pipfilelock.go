package packagecheck

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/garagon/aguara/internal/jsonfields"
)

// maxPipfileSpec is the newest Pipfile.lock "pipfile-spec" this parser
// understands. Pipenv has written 6 for years; a newer value means a
// format change this release cannot vouch for.
const maxPipfileSpec = 6

// pipfileNonRegistryKeys mark entries Pipenv installs from a VCS
// checkout, a local path or a file/URL rather than from an index.
var pipfileNonRegistryKeys = []string{"git", "hg", "svn", "bzr", "path", "file", "uri"}

// pipfileEntry is the subset of a Pipfile.lock package entry the parser
// needs. Keys are matched exactly (encoding/json alone would also accept
// "Version" or "GIT"); a repeated key keeps its final value.
type pipfileEntry struct {
	Version     string
	Editable    bool
	NonRegistry bool
}

func (e *pipfileEntry) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw == nil {
		return fmt.Errorf("package entry must be an object")
	}
	var next pipfileEntry
	if err := jsonfields.Decode(data,
		jsonfields.Field{Name: "version", To: &next.Version},
		jsonfields.Field{Name: "editable", To: &next.Editable}); err != nil {
		return err
	}
	for _, k := range pipfileNonRegistryKeys {
		if _, ok := raw[k]; ok {
			next.NonRegistry = true
		}
	}
	*e = next
	return nil
}

// ParsePipfileLock reads Pipfile.lock and returns the index packages of
// every category: `default`, `develop`, and custom categories, which
// Pipenv writes as additional top-level keys. Entries with a VCS, path
// or file source, and editable entries, are skipped. A pinned version
// is written as "==x.y" (or "===x.y"); an entry without one exact pin
// is returned as unpinned. Group is the category name, empty for
// `default`. Pipfile (the manifest) is not read. No Pipenv execution,
// no network.
func ParsePipfileLock(target Target) ([]PackageRef, error) {
	data, err := readManifest(target.Path, "Pipfile.lock")
	if err != nil {
		return nil, fmt.Errorf("read Pipfile.lock: %w", err)
	}
	return parsePipfileLockBytes(data, target.Path)
}

func parsePipfileLockBytes(data []byte, path string) ([]PackageRef, error) {
	if err := checkJSONNodeBudget(data, "Pipfile.lock"); err != nil {
		return nil, err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil || top == nil {
		return nil, fmt.Errorf("parse Pipfile.lock: expected a JSON object")
	}
	if meta, ok := top["_meta"]; ok {
		var spec *int
		if err := jsonfields.Decode(meta, jsonfields.Field{Name: "pipfile-spec", To: &spec}); err != nil {
			return nil, fmt.Errorf("parse Pipfile.lock: invalid _meta")
		}
		if spec != nil && (*spec < 1 || *spec > maxPipfileSpec) {
			return nil, fmt.Errorf("parse Pipfile.lock: unsupported pipfile-spec %d (this release reads up to %d)", *spec, maxPipfileSpec)
		}
	}
	categories := make([]string, 0, len(top))
	for k := range top {
		if k != "_meta" {
			categories = append(categories, k)
		}
	}
	sort.Slice(categories, func(i, j int) bool {
		return pipfileCategoryRank(categories[i]) < pipfileCategoryRank(categories[j]) ||
			(pipfileCategoryRank(categories[i]) == pipfileCategoryRank(categories[j]) && categories[i] < categories[j])
	})

	coll := newPythonRefCollector("Pipfile.lock")
	for _, category := range categories {
		var entries jsonfields.Map[pipfileEntry]
		if err := json.Unmarshal(top[category], &entries); err != nil {
			return nil, fmt.Errorf("parse Pipfile.lock: category %q: %w", category, err)
		}
		names := make([]string, 0, len(entries))
		for name := range entries {
			names = append(names, name)
		}
		sort.Strings(names)
		group := category
		if category == "default" {
			group = ""
		}
		for _, name := range names {
			if name == "" {
				return nil, fmt.Errorf("parse Pipfile.lock: category %q has an empty package name", category)
			}
			entry := entries[name]
			if entry.NonRegistry || entry.Editable {
				continue
			}
			ref := PackageRef{Name: name, Path: path, Source: "Pipfile.lock", Group: group}
			if v, ok := pipfilePinnedVersion(entry.Version); ok {
				ref.Version = v
			} else {
				ref.Unpinned = true
				ref.Constraint = strings.TrimSpace(entry.Version)
			}
			if err := coll.add(ref); err != nil {
				return nil, err
			}
		}
	}
	return coll.refs, nil
}

// pipfilePinnedVersion extracts the version from "==x.y" or "===x.y".
// Wildcards ("==1.*"), ranges and "*" are not exact pins.
func pipfilePinnedVersion(spec string) (string, bool) {
	spec = strings.TrimSpace(spec)
	var v string
	switch {
	case strings.HasPrefix(spec, "==="):
		v = strings.TrimSpace(spec[3:])
	case strings.HasPrefix(spec, "=="):
		v = strings.TrimSpace(spec[2:])
	default:
		return "", false
	}
	if v == "" || strings.ContainsAny(v, "*,;<>=!~ ") {
		return "", false
	}
	return v, true
}

func pipfileCategoryRank(c string) int {
	switch c {
	case "default":
		return 0
	case "develop":
		return 1
	default:
		return 2
	}
}

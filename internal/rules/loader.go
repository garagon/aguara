package rules

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadFromFS loads rules from an embed.FS or any fs.FS.
func LoadFromFS(fsys fs.FS) ([]RawRule, error) {
	var all []RawRule
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !isYAML(path) {
			return nil
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		rules, err := parseMultiDocYAML(data, path)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", path, err)
		}
		all = append(all, rules...)
		return nil
	})
	return all, err
}

// maxRuleFileSize is the maximum size for a single YAML rule file (1 MB).
const maxRuleFileSize = 1 << 20

// SkippedFile is a rule file LoadFromDir did not load.
type SkippedFile struct {
	Path   string
	Reason string
}

// LoadFromDir loads rules from a directory on disk. Unknown YAML keys are
// rejected. Files larger than 1 MB are not loaded; they are returned in
// skipped so the caller can report them instead of losing the rules
// silently.
func LoadFromDir(dir string) (rules []RawRule, skipped []SkippedFile, err error) {
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !isYAML(path) {
			return nil
		}
		if info.Size() > maxRuleFileSize {
			skipped = append(skipped, SkippedFile{
				Path:   path,
				Reason: fmt.Sprintf("rule file is %d bytes, over the %d-byte limit; its rules were not loaded", info.Size(), maxRuleFileSize),
			})
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		parsed, err := parseMultiDocYAML(data, path)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", path, err)
		}
		rules = append(rules, parsed...)
		return nil
	})
	return rules, skipped, err
}

// UniqueDirs returns dirs without empty entries and without repeats of a
// directory already listed (compared after filepath.Clean), keeping the
// order of first appearance. Loading the same directory twice would define
// every rule in it twice.
func UniqueDirs(dirs []string) []string {
	var out []string
	seen := make(map[string]bool, len(dirs))
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		key := filepath.Clean(dir)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, dir)
	}
	return out
}

// parseMultiDocYAML splits a YAML file on "---" boundaries and parses each
// document. Empty documents are skipped. A document with content but no id
// is kept so that Compile reports it, rather than dropping the rule unseen.
func parseMultiDocYAML(data []byte, source string) ([]RawRule, error) {
	var rules []RawRule
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	for {
		var raw RawRule
		err := decoder.Decode(&raw)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		if raw.ID == "" && reflect.ValueOf(raw).IsZero() {
			continue
		}
		raw.Source = source
		rules = append(rules, raw)
	}
	return rules, nil
}

func isYAML(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}

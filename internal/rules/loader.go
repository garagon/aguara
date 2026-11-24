package rules

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
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
		rules, err := parseMultiDocYAML(data)
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

// LoadFromDir loads rules from a directory on disk.
// Files larger than 1 MB are skipped. Unknown YAML keys are rejected.
func LoadFromDir(dir string) ([]RawRule, error) {
	var all []RawRule
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !isYAML(path) {
			return nil
		}
		if info.Size() > maxRuleFileSize {
			fmt.Fprintf(os.Stderr, "warning: skipping oversized rule file %s (%d bytes, max %d)\n", path, info.Size(), maxRuleFileSize)
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		rules, err := parseMultiDocYAML(data)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", path, err)
		}
		all = append(all, rules...)
		return nil
	})
	return all, err
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

// parseMultiDocYAML splits a YAML file on "---" boundaries and parses each document.
func parseMultiDocYAML(data []byte) ([]RawRule, error) {
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
		if raw.ID != "" {
			rules = append(rules, raw)
		}
	}
	return rules, nil
}

func isYAML(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}

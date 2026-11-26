// Package config loads and applies .aguara.yml configuration files
// for rule overrides, severity adjustments, and scan settings.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	// DefaultMaxFileSize is the default maximum file size (50 MB).
	DefaultMaxFileSize int64 = 50 << 20
	// MinMaxFileSize is the minimum allowed value for max_file_size (1 MB).
	MinMaxFileSize int64 = 1 << 20
	// MaxMaxFileSize is the maximum allowed value for max_file_size (500 MB).
	MaxMaxFileSize int64 = 500 << 20
)

// ValidateMaxFileSize checks that a max-file-size value is within bounds.
// Returns the value clamped to [MinMaxFileSize, MaxMaxFileSize] or an error.
func ValidateMaxFileSize(v int64) (int64, error) {
	if v < MinMaxFileSize {
		return 0, fmt.Errorf("max-file-size %d bytes is below minimum (%d bytes / 1 MB)", v, MinMaxFileSize)
	}
	if v > MaxMaxFileSize {
		return 0, fmt.Errorf("max-file-size %d bytes exceeds maximum (%d bytes / 500 MB)", v, MaxMaxFileSize)
	}
	return v, nil
}

// RuleOverride allows per-rule severity, disable, or tool-scoped filtering.
// ApplyToTools and ExemptTools are mutually exclusive.
type RuleOverride struct {
	Severity     string   `yaml:"severity,omitempty"`
	Disabled     bool     `yaml:"disabled,omitempty"`
	ApplyToTools []string `yaml:"apply_to_tools,omitempty"`
	ExemptTools  []string `yaml:"exempt_tools,omitempty"`
}

// Config represents the .aguara.yml configuration file.
type Config struct {
	// Paths is accepted for compatibility with files that uncommented the
	// "paths" example earlier `aguara init` versions scaffolded. Nothing
	// reads it; Load adds a notice when it is set.
	Paths         []string                `yaml:"paths,omitempty"`
	Ignore        []string                `yaml:"ignore,omitempty"`
	Severity      string                  `yaml:"severity,omitempty"`
	FailOn        string                  `yaml:"fail_on,omitempty"`
	Format        string                  `yaml:"format,omitempty"`
	Rules         string                  `yaml:"rules,omitempty"`
	DisableRules  []string                `yaml:"disable_rules,omitempty"`
	RuleOverrides map[string]RuleOverride `yaml:"rule_overrides,omitempty"`
	MaxFileSize   int64                   `yaml:"max_file_size,omitempty"`
	Baseline      string                  `yaml:"baseline,omitempty"`

	// Source is the path of the file Load read, or "" when no config file
	// was found.
	Source string `yaml:"-"`
	// Warnings lists keys in the file that Aguara does not recognize (for
	// example a misspelled "disabled_rules"). They are ignored, so callers
	// that apply the file should show these warnings to the user.
	Warnings []string `yaml:"-"`
	// Notices lists keys that are accepted but have no effect, such as
	// "paths".
	Notices []string `yaml:"-"`
}

// Load reads the .aguara.yml or .aguara.yaml config file from the given path.
// If path is a file, its parent directory is used. If no config file is found,
// it returns a zero Config (not an error). Unknown keys are not an error, for
// compatibility with existing files; they are listed in Config.Warnings.
func Load(dir string) (Config, error) {
	if info, err := os.Stat(dir); err == nil && !info.IsDir() {
		dir = filepath.Dir(dir)
	}
	for _, name := range []string{".aguara.yml", ".aguara.yaml"} {
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return Config{}, fmt.Errorf("reading %s: %w", path, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return Config{}, fmt.Errorf("%s is a symbolic link (rejected for security)", path)
		}
		if info.Size() > 1<<20 {
			return Config{}, fmt.Errorf("config file too large: %s (%d bytes, max 1 MB)", path, info.Size())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return Config{}, fmt.Errorf("reading %s: %w", path, err)
		}
		var cfg Config
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return Config{}, fmt.Errorf("parsing %s: %w", path, err)
		}
		// Validate mutually exclusive tool-scoped fields
		for id, ovr := range cfg.RuleOverrides {
			if len(ovr.ApplyToTools) > 0 && len(ovr.ExemptTools) > 0 {
				return Config{}, fmt.Errorf("rule %s: apply_to_tools and exempt_tools are mutually exclusive", id)
			}
		}
		cfg.Source = path
		cfg.Warnings, cfg.Notices = unknownKeys(path, data)
		return cfg, nil
	}
	return Config{}, nil
}

// unknownKeys reports top-level keys and rule_overrides entry keys that do
// not map to a Config or RuleOverride field. yaml.Unmarshal ignores them, so
// a misspelled key silently loses the setting. The second result notes
// known keys that have no effect.
func unknownKeys(path string, data []byte) ([]string, []string) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil || len(doc.Content) == 0 {
		return nil, nil
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, nil
	}
	topKeys := yamlFieldNames(reflect.TypeFor[Config]())
	overrideKeys := yamlFieldNames(reflect.TypeFor[RuleOverride]())
	var warnings, notices []string
	for i := 0; i+1 < len(root.Content); i += 2 {
		key, value := root.Content[i], root.Content[i+1]
		if key.Value == "<<" {
			continue // merge key; its contents are checked by the decoder
		}
		if key.Value == "paths" {
			notices = append(notices, fmt.Sprintf("%s:%d: %q has no effect; name the paths to scan on the command line", path, key.Line, key.Value))
			continue
		}
		if !topKeys[key.Value] {
			warnings = append(warnings, fmt.Sprintf("%s:%d: unknown key %q (ignored)", path, key.Line, key.Value))
			continue
		}
		if key.Value != "rule_overrides" || value.Kind != yaml.MappingNode {
			continue
		}
		for j := 0; j+1 < len(value.Content); j += 2 {
			id, body := value.Content[j], value.Content[j+1]
			if body.Kind != yaml.MappingNode {
				continue
			}
			for k := 0; k+1 < len(body.Content); k += 2 {
				field := body.Content[k]
				if field.Value != "<<" && !overrideKeys[field.Value] {
					warnings = append(warnings, fmt.Sprintf("%s:%d: unknown key %q in rule_overrides.%s (ignored)", path, field.Line, field.Value, id.Value))
				}
			}
		}
	}
	return warnings, notices
}

// yamlFieldNames returns the YAML key of every field of struct type t.
func yamlFieldNames(t reflect.Type) map[string]bool {
	names := make(map[string]bool, t.NumField())
	for i := range t.NumField() {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("yaml"), ",")
		if name != "" && name != "-" {
			names[name] = true
		}
	}
	return names
}

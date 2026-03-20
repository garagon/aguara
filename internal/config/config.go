// Package config loads and applies .aguara.yml configuration files
// for rule overrides, severity adjustments, and scan settings.
package config

import (
	"fmt"
	"os"
	"path/filepath"

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
	Paths         []string                `yaml:"paths,omitempty"`
	Ignore        []string                `yaml:"ignore,omitempty"`
	Severity      string                  `yaml:"severity,omitempty"`
	FailOn        string                  `yaml:"fail_on,omitempty"`
	Format        string                  `yaml:"format,omitempty"`
	Rules         string                  `yaml:"rules,omitempty"`
	DisableRules  []string                `yaml:"disable_rules,omitempty"`
	RuleOverrides map[string]RuleOverride `yaml:"rule_overrides,omitempty"`
	MaxFileSize   int64                   `yaml:"max_file_size,omitempty"`
}

// Load reads the .aguara.yml or .aguara.yaml config file from the given path.
// If path is a file, its parent directory is used. If no config file is found,
// it returns a zero Config (not an error).
func Load(dir string) (Config, error) {
	if info, err := os.Stat(dir); err == nil && !info.IsDir() {
		dir = filepath.Dir(dir)
	}
	for _, name := range []string{".aguara.yml", ".aguara.yaml"} {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return Config{}, fmt.Errorf("reading %s: %w", path, err)
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
		return cfg, nil
	}
	return Config{}, nil
}

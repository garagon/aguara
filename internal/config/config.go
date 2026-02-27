// Package config loads and applies .aguara.yml configuration files
// for rule overrides, severity adjustments, and scan settings.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// RuleOverride allows per-rule severity or disable.
type RuleOverride struct {
	Severity string `yaml:"severity,omitempty"`
	Disabled bool   `yaml:"disabled,omitempty"`
}

// Config represents the .aguara.yml configuration file.
type Config struct {
	Paths         []string                `yaml:"paths,omitempty"`
	Ignore        []string                `yaml:"ignore,omitempty"`
	Severity      string                  `yaml:"severity,omitempty"`
	FailOn        string                  `yaml:"fail_on,omitempty"`
	Format        string                  `yaml:"format,omitempty"`
	Rules         string                  `yaml:"rules,omitempty"`
	RuleOverrides map[string]RuleOverride `yaml:"rule_overrides,omitempty"`
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
		return cfg, nil
	}
	return Config{}, nil
}

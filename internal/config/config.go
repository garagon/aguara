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

// Load reads the .aguara.yml or .aguara.yaml config file from the given directory.
// If no config file is found, it returns a zero Config (not an error).
func Load(dir string) (Config, error) {
	for _, name := range []string{".aguara.yml", ".aguara.yaml"} {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
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

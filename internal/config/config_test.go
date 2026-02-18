package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/garagon/aguara/internal/config"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	data := []byte(`
paths:
  - src/
  - lib/
ignore:
  - "*.log"
  - vendor/
severity: high
fail_on: critical
format: sarif
rules: custom-rules/
rule_overrides:
  PROMPT_INJECTION_001:
    severity: medium
  EXFIL_005:
    disabled: true
`)
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".aguara.yml"), data, 0644))

	cfg, err := config.Load(dir)
	require.NoError(t, err)
	require.Equal(t, []string{"src/", "lib/"}, cfg.Paths)
	require.Equal(t, []string{"*.log", "vendor/"}, cfg.Ignore)
	require.Equal(t, "high", cfg.Severity)
	require.Equal(t, "critical", cfg.FailOn)
	require.Equal(t, "sarif", cfg.Format)
	require.Equal(t, "custom-rules/", cfg.Rules)
	require.Len(t, cfg.RuleOverrides, 2)
	require.Equal(t, "medium", cfg.RuleOverrides["PROMPT_INJECTION_001"].Severity)
	require.True(t, cfg.RuleOverrides["EXFIL_005"].Disabled)
}

func TestLoadConfigYAMLExtension(t *testing.T) {
	dir := t.TempDir()
	data := []byte("severity: medium\n")
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".aguara.yaml"), data, 0644))

	cfg, err := config.Load(dir)
	require.NoError(t, err)
	require.Equal(t, "medium", cfg.Severity)
}

func TestLoadConfigMissing(t *testing.T) {
	dir := t.TempDir()
	cfg, err := config.Load(dir)
	require.NoError(t, err)
	require.Equal(t, config.Config{}, cfg)
}

func TestLoadConfigInvalid(t *testing.T) {
	dir := t.TempDir()
	data := []byte("{{invalid yaml")
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".aguara.yml"), data, 0644))

	_, err := config.Load(dir)
	require.Error(t, err)
	require.Contains(t, err.Error(), "parsing")
}

func TestLoadConfigPrecedence(t *testing.T) {
	// .aguara.yml takes priority over .aguara.yaml
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".aguara.yml"), []byte("severity: high\n"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".aguara.yaml"), []byte("severity: low\n"), 0644))

	cfg, err := config.Load(dir)
	require.NoError(t, err)
	require.Equal(t, "high", cfg.Severity)
}

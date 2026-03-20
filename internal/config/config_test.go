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

func TestValidateMaxFileSize(t *testing.T) {
	tests := []struct {
		name    string
		input   int64
		wantErr bool
	}{
		{"valid 50MB", 50 << 20, false},
		{"valid minimum 1MB", 1 << 20, false},
		{"valid maximum 500MB", 500 << 20, false},
		{"valid 100MB", 100 << 20, false},
		{"too small 512KB", 512 << 10, true},
		{"too small zero", 0, true},
		{"too large 501MB", 501 << 20, true},
		{"too large 1GB", 1 << 30, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := config.ValidateMaxFileSize(tt.input)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.input, v)
			}
		})
	}
}

func TestLoadConfigMaxFileSize(t *testing.T) {
	dir := t.TempDir()
	data := []byte("max_file_size: 104857600\n") // 100 MB
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".aguara.yml"), data, 0644))

	cfg, err := config.Load(dir)
	require.NoError(t, err)
	require.Equal(t, int64(104857600), cfg.MaxFileSize)
}

func TestLoadConfigDisableRules(t *testing.T) {
	dir := t.TempDir()
	data := []byte(`
disable_rules:
  - CRED_004
  - EXFIL_005
  - PROMPT_INJECTION_001
`)
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".aguara.yml"), data, 0644))

	cfg, err := config.Load(dir)
	require.NoError(t, err)
	require.Equal(t, []string{"CRED_004", "EXFIL_005", "PROMPT_INJECTION_001"}, cfg.DisableRules)
}

func TestLoadConfigToolScopedRules(t *testing.T) {
	dir := t.TempDir()
	data := []byte(`
rule_overrides:
  TC-005:
    apply_to_tools:
      - Bash
  MCPCFG_004:
    exempt_tools:
      - WebFetch
`)
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".aguara.yml"), data, 0644))

	cfg, err := config.Load(dir)
	require.NoError(t, err)
	require.Equal(t, []string{"Bash"}, cfg.RuleOverrides["TC-005"].ApplyToTools)
	require.Equal(t, []string{"WebFetch"}, cfg.RuleOverrides["MCPCFG_004"].ExemptTools)
}

func TestLoadConfigToolScopedMutuallyExclusive(t *testing.T) {
	dir := t.TempDir()
	data := []byte(`
rule_overrides:
  TC-005:
    apply_to_tools:
      - Bash
    exempt_tools:
      - Edit
`)
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".aguara.yml"), data, 0644))

	_, err := config.Load(dir)
	require.Error(t, err)
	require.Contains(t, err.Error(), "mutually exclusive")
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

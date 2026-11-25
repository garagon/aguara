package rules_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/garagon/aguara/internal/rules"
	"github.com/stretchr/testify/require"
)

func TestCompileCWE(t *testing.T) {
	raw := func(cwe ...string) rules.RawRule {
		return rules.RawRule{
			ID: "TEST_CWE", Name: "CWE", Severity: "LOW", Category: "test", CWE: cwe,
			Patterns: []rules.RawPattern{{Type: rules.PatternContains, Value: "a"}},
		}
	}
	compiled, err := rules.Compile(raw())
	require.NoError(t, err)
	require.Nil(t, compiled.CWE, "the field is optional")

	compiled, err = rules.Compile(raw(" cwe-798 ", "CWE-259"))
	require.NoError(t, err)
	require.Equal(t, []string{"CWE-798", "CWE-259"}, compiled.CWE)

	for _, bad := range []string{"798", "CWE-", "CWE-0798", "CWE-12a", "OWASP-A01"} {
		_, err := rules.Compile(raw(bad))
		require.ErrorContains(t, err, "invalid cwe", bad)
	}
	_, err = rules.Compile(raw("CWE-78", "cwe-78"))
	require.ErrorContains(t, err, "duplicate cwe")

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "r.yaml"), []byte(`id: TEST_YAML_CWE
name: CWE
severity: LOW
category: test
cwe: [CWE-494]
patterns:
  - type: contains
    value: a
`), 0o600))
	raws, _, err := rules.LoadFromDir(dir)
	require.NoError(t, err)
	require.Equal(t, []string{"CWE-494"}, raws[0].CWE)
}

package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/garagon/aguara/internal/engine/nlp"
	"github.com/garagon/aguara/internal/engine/pattern"
	"github.com/garagon/aguara/internal/rules"
	"github.com/garagon/aguara/internal/rules/builtin"
	"github.com/garagon/aguara/internal/scanner"
	"github.com/stretchr/testify/require"
)

func testdataDir(t *testing.T) string {
	t.Helper()
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "testdata")
}

func setupScanner(t *testing.T) *scanner.Scanner {
	t.Helper()
	rawRules, err := rules.LoadFromFS(builtin.FS())
	require.NoError(t, err)

	compiled, errs := rules.CompileAll(rawRules)
	require.Empty(t, errs)

	s := scanner.New(2)
	s.RegisterAnalyzer(pattern.NewMatcher(compiled))
	s.RegisterAnalyzer(nlp.NewInjectionAnalyzer())
	return s
}

func TestIntegrationMaliciousPromptInjection(t *testing.T) {
	dir := filepath.Join(testdataDir(t), "malicious", "prompt-injection-basic")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skip("testdata not found")
	}

	s := setupScanner(t)
	result, err := s.Scan(context.Background(), dir)
	require.NoError(t, err)
	require.Greater(t, len(result.Findings), 0, "should detect findings in prompt-injection-basic")

	// Should have at least one CRITICAL finding
	hasCritical := false
	for _, f := range result.Findings {
		if f.Severity == scanner.SeverityCritical {
			hasCritical = true
			break
		}
	}
	require.True(t, hasCritical, "should have at least one CRITICAL finding")
}

func TestIntegrationMaliciousExfil(t *testing.T) {
	dir := filepath.Join(testdataDir(t), "malicious", "exfil-webhook")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skip("testdata not found")
	}

	s := setupScanner(t)
	result, err := s.Scan(context.Background(), dir)
	require.NoError(t, err)
	require.Greater(t, len(result.Findings), 0, "should detect findings in exfil-webhook")
}

func TestIntegrationMaliciousCredentialLeak(t *testing.T) {
	dir := filepath.Join(testdataDir(t), "malicious", "credential-leak")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skip("testdata not found")
	}

	s := setupScanner(t)
	result, err := s.Scan(context.Background(), dir)
	require.NoError(t, err)
	require.Greater(t, len(result.Findings), 0, "should detect findings in credential-leak")
}

func TestIntegrationMaliciousHiddenInjection(t *testing.T) {
	dir := filepath.Join(testdataDir(t), "malicious", "hidden-injection")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skip("testdata not found")
	}

	s := setupScanner(t)
	result, err := s.Scan(context.Background(), dir)
	require.NoError(t, err)
	require.Greater(t, len(result.Findings), 0, "should detect findings in hidden-injection")
}

func TestIntegrationMaliciousCombinedAttack(t *testing.T) {
	dir := filepath.Join(testdataDir(t), "malicious", "combined-attack")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skip("testdata not found")
	}

	s := setupScanner(t)
	result, err := s.Scan(context.Background(), dir)
	require.NoError(t, err)
	require.Greater(t, len(result.Findings), 5, "combined attack should have many findings")
}

func TestIntegrationBenignSimple(t *testing.T) {
	dir := filepath.Join(testdataDir(t), "benign", "simple-skill")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skip("testdata not found")
	}

	s := setupScanner(t)
	result, err := s.Scan(context.Background(), dir)
	require.NoError(t, err)
	require.Empty(t, result.Findings, "benign simple-skill should have 0 findings")
}

func TestIntegrationBenignComplex(t *testing.T) {
	dir := filepath.Join(testdataDir(t), "benign", "complex-skill")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skip("testdata not found")
	}

	s := setupScanner(t)
	result, err := s.Scan(context.Background(), dir)
	require.NoError(t, err)
	require.Empty(t, result.Findings, "benign complex-skill should have 0 findings")
}

func TestIntegrationBenignDocumentation(t *testing.T) {
	dir := filepath.Join(testdataDir(t), "benign", "documentation-skill")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skip("testdata not found")
	}

	s := setupScanner(t)
	result, err := s.Scan(context.Background(), dir)
	require.NoError(t, err)
	require.Empty(t, result.Findings, "benign documentation-skill should have 0 findings")
}

func TestIntegrationMaliciousEncodedPayload(t *testing.T) {
	dir := filepath.Join(testdataDir(t), "malicious", "encoded-payload")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skip("testdata not found")
	}

	s := setupScanner(t)
	result, err := s.Scan(context.Background(), dir)
	require.NoError(t, err)
	require.Greater(t, len(result.Findings), 0, "should detect findings in encoded-payload")

	// Should detect the base64 payload via decoder
	hasDecoder := false
	for _, f := range result.Findings {
		if f.Analyzer == "pattern-decoder" {
			hasDecoder = true
			break
		}
	}
	require.True(t, hasDecoder, "should have at least one finding from pattern-decoder")
}

func TestIntegrationMaliciousMCPToolPoisoning(t *testing.T) {
	dir := filepath.Join(testdataDir(t), "malicious", "mcp-tool-poisoning")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skip("testdata not found")
	}

	s := setupScanner(t)
	result, err := s.Scan(context.Background(), dir)
	require.NoError(t, err)
	require.Greater(t, len(result.Findings), 0, "should detect findings in mcp-tool-poisoning")

	// Should have at least one finding from MCP category
	hasMCP := false
	for _, f := range result.Findings {
		if f.Category == "mcp-attack" {
			hasMCP = true
			break
		}
	}
	require.True(t, hasMCP, "should have at least one mcp-attack finding")
}

func TestIntegrationMaliciousSSRFMetadata(t *testing.T) {
	dir := filepath.Join(testdataDir(t), "malicious", "ssrf-metadata")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skip("testdata not found")
	}

	s := setupScanner(t)
	result, err := s.Scan(context.Background(), dir)
	require.NoError(t, err)
	require.Greater(t, len(result.Findings), 0, "should detect findings in ssrf-metadata")

	hasSSRF := false
	for _, f := range result.Findings {
		if f.Category == "ssrf-cloud" {
			hasSSRF = true
			break
		}
	}
	require.True(t, hasSSRF, "should have at least one ssrf-cloud finding")
}

func TestIntegrationMaliciousSupplyChain(t *testing.T) {
	dir := filepath.Join(testdataDir(t), "malicious", "supply-chain-attack")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skip("testdata not found")
	}

	s := setupScanner(t)
	result, err := s.Scan(context.Background(), dir)
	require.NoError(t, err)
	require.Greater(t, len(result.Findings), 0, "should detect findings in supply-chain-attack")

	hasSupply := false
	for _, f := range result.Findings {
		if f.Category == "supply-chain" {
			hasSupply = true
			break
		}
	}
	require.True(t, hasSupply, "should have at least one supply-chain finding")
}

func TestIntegrationMaliciousUnicodeObfuscation(t *testing.T) {
	dir := filepath.Join(testdataDir(t), "malicious", "unicode-obfuscation")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skip("testdata not found")
	}

	s := setupScanner(t)
	result, err := s.Scan(context.Background(), dir)
	require.NoError(t, err)
	require.Greater(t, len(result.Findings), 0, "should detect findings in unicode-obfuscation")
}

func TestIntegrationBenignMCPServer(t *testing.T) {
	dir := filepath.Join(testdataDir(t), "benign", "mcp-server-legit")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skip("testdata not found")
	}

	s := setupScanner(t)
	result, err := s.Scan(context.Background(), dir)
	require.NoError(t, err)
	require.Empty(t, result.Findings, "benign mcp-server-legit should have 0 findings")
}

func TestIntegrationBenignSecurityTooling(t *testing.T) {
	dir := filepath.Join(testdataDir(t), "benign", "security-tooling")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skip("testdata not found")
	}

	s := setupScanner(t)
	result, err := s.Scan(context.Background(), dir)
	require.NoError(t, err)
	require.Empty(t, result.Findings, "benign security-tooling should have 0 findings")
}

func TestIntegrationBenignNpmProject(t *testing.T) {
	dir := filepath.Join(testdataDir(t), "benign", "npm-project")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skip("testdata not found")
	}

	s := setupScanner(t)
	result, err := s.Scan(context.Background(), dir)
	require.NoError(t, err)
	require.Empty(t, result.Findings, "benign npm-project should have 0 findings")
}

func TestIntegrationDetectionRate(t *testing.T) {
	root := filepath.Join(testdataDir(t), "malicious")
	if _, err := os.Stat(root); os.IsNotExist(err) {
		t.Skip("testdata not found")
	}

	entries, err := os.ReadDir(root)
	require.NoError(t, err)

	s := setupScanner(t)
	detected := 0
	total := 0

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		total++
		dir := filepath.Join(root, entry.Name())
		result, err := s.Scan(context.Background(), dir)
		require.NoError(t, err)
		if len(result.Findings) > 0 {
			detected++
		}
	}

	rate := float64(detected) / float64(total)
	require.GreaterOrEqual(t, rate, 0.9,
		"detection rate %.1f%% is below 90%% threshold (%d/%d)", rate*100, detected, total)
}

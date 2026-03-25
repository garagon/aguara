package incident

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsCompromised(t *testing.T) {
	assert.NotNil(t, IsCompromised("litellm", "1.82.7"))
	assert.NotNil(t, IsCompromised("litellm", "1.82.8"))
	assert.Nil(t, IsCompromised("litellm", "1.82.6"))
	assert.Nil(t, IsCompromised("requests", "2.31.0"))
}

func TestReadInstalledPackages(t *testing.T) {
	dir := t.TempDir()

	// Create a fake dist-info with METADATA
	distInfo := filepath.Join(dir, "litellm-1.82.8.dist-info")
	require.NoError(t, os.Mkdir(distInfo, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(distInfo, "METADATA"), []byte(
		"Metadata-Version: 2.1\nName: litellm\nVersion: 1.82.8\nSummary: LLM proxy\n",
	), 0644))

	// Create a safe package
	safeInfo := filepath.Join(dir, "requests-2.31.0.dist-info")
	require.NoError(t, os.Mkdir(safeInfo, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(safeInfo, "METADATA"), []byte(
		"Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n",
	), 0644))

	pkgs := readInstalledPackages(dir)
	require.Len(t, pkgs, 2)

	names := map[string]string{}
	for _, p := range pkgs {
		names[p.Name] = p.Version
	}
	assert.Equal(t, "1.82.8", names["litellm"])
	assert.Equal(t, "2.31.0", names["requests"])
}

func TestCheckDetectsCompromisedPackage(t *testing.T) {
	dir := t.TempDir()

	distInfo := filepath.Join(dir, "litellm-1.82.8.dist-info")
	require.NoError(t, os.Mkdir(distInfo, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(distInfo, "METADATA"), []byte(
		"Metadata-Version: 2.1\nName: litellm\nVersion: 1.82.8\n",
	), 0644))

	result, err := Check(CheckOptions{Path: dir})
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(result.Findings), 1)
	assert.Equal(t, SevCritical, result.Findings[0].Severity)
	assert.Contains(t, result.Findings[0].Title, "litellm")
}

func TestCheckDetectsMaliciousPth(t *testing.T) {
	dir := t.TempDir()

	pth := filepath.Join(dir, "evil.pth")
	require.NoError(t, os.WriteFile(pth, []byte(
		"import subprocess; subprocess.Popen(['python', '/tmp/payload.py'])\n",
	), 0644))

	result, err := Check(CheckOptions{Path: dir})
	require.NoError(t, err)

	hasPth := false
	for _, f := range result.Findings {
		if f.Severity == SevCritical && f.Path == pth {
			hasPth = true
		}
	}
	assert.True(t, hasPth, "should detect malicious .pth file")
}

func TestCheckSkipsKnownSafePth(t *testing.T) {
	dir := t.TempDir()

	// _virtualenv.pth is a known-safe file
	pth := filepath.Join(dir, "_virtualenv.pth")
	require.NoError(t, os.WriteFile(pth, []byte("import _virtualenv\n"), 0644))

	// distutils-precedence.pth is also known-safe
	pth2 := filepath.Join(dir, "distutils-precedence.pth")
	require.NoError(t, os.WriteFile(pth2, []byte("import _distutils_hack; _distutils_hack.add_shim()\n"), 0644))

	// But evil.pth should still be flagged
	evil := filepath.Join(dir, "evil.pth")
	require.NoError(t, os.WriteFile(evil, []byte("import subprocess; subprocess.Popen(['evil'])\n"), 0644))

	result, err := Check(CheckOptions{Path: dir})
	require.NoError(t, err)

	for _, f := range result.Findings {
		assert.NotContains(t, f.Path, "_virtualenv.pth", "known-safe _virtualenv.pth should be skipped")
		assert.NotContains(t, f.Path, "distutils-precedence.pth", "known-safe distutils-precedence.pth should be skipped")
	}

	hasEvil := false
	for _, f := range result.Findings {
		if f.Path == evil {
			hasEvil = true
		}
	}
	assert.True(t, hasEvil, "evil.pth should still be flagged")
}

func TestCheckCleanPth(t *testing.T) {
	dir := t.TempDir()

	// Legitimate .pth with only paths
	pth := filepath.Join(dir, "safe.pth")
	require.NoError(t, os.WriteFile(pth, []byte(
		"/usr/local/lib/python3.12/site-packages\n./vendor\n",
	), 0644))

	result, err := Check(CheckOptions{Path: dir})
	require.NoError(t, err)

	for _, f := range result.Findings {
		assert.NotContains(t, f.Path, "safe.pth", "legitimate .pth should not be flagged")
	}
}

func TestCheckEmptyEnvironment(t *testing.T) {
	dir := t.TempDir()

	result, err := Check(CheckOptions{Path: dir})
	require.NoError(t, err)
	assert.Equal(t, 0, result.PackagesRead)
	// Only persistence findings could exist (from home dir check)
	for _, f := range result.Findings {
		assert.NotEqual(t, "known compromised", f.Title)
	}
}

func TestCheckCredentialFiles(t *testing.T) {
	creds := checkCredentialFiles()
	require.NotEmpty(t, creds, "should always return credential list")

	// Verify all expected paths are present
	paths := map[string]bool{}
	for _, c := range creds {
		paths[c.Path] = true
		assert.NotEmpty(t, c.Guidance)
	}
	assert.True(t, paths["~/.ssh/id_rsa"])
	assert.True(t, paths["~/.aws/credentials"])
	assert.True(t, paths["~/.kube/config"])
}

func TestParseMetadata(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "METADATA")
	require.NoError(t, os.WriteFile(path, []byte(
		"Metadata-Version: 2.1\nName: Flask\nVersion: 3.0.1\nSummary: Web framework\n\nFull description here.\n",
	), 0644))

	pkg := parseMetadata(path)
	assert.Equal(t, "flask", pkg.Name) // lowercased
	assert.Equal(t, "3.0.1", pkg.Version)
}

func TestCheckMultipleCompromised(t *testing.T) {
	dir := t.TempDir()

	// Compromised package
	d1 := filepath.Join(dir, "litellm-1.82.7.dist-info")
	require.NoError(t, os.Mkdir(d1, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(d1, "METADATA"), []byte(
		"Name: litellm\nVersion: 1.82.7\n",
	), 0644))

	// Malicious .pth
	require.NoError(t, os.WriteFile(filepath.Join(dir, "litellm_init.pth"), []byte(
		"import subprocess; subprocess.Popen(['python', '-c', 'malware'])\n",
	), 0644))

	result, err := Check(CheckOptions{Path: dir})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(result.Findings), 2, "should find both package and .pth")
}

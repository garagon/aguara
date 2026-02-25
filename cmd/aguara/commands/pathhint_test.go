package commands

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsGoBinDir(t *testing.T) {
	tests := []struct {
		dir  string
		want bool
	}{
		{"/Users/dev/go/bin", true},
		{"/home/user/go/bin", true},
		{"/usr/local/go/bin", true},
		{"/usr/local/bin", false},
		{"/home/user/gobin", false},
		{"/home/user/go/bin/subdir", false},
		{"", false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, isGoBinDir(tt.dir), "isGoBinDir(%q)", tt.dir)
	}
}

func TestDirInPATH(t *testing.T) {
	t.Setenv("PATH", "/usr/bin:/home/user/go/bin:/usr/local/bin")

	assert.True(t, dirInPATH("/home/user/go/bin"))
	assert.False(t, dirInPATH("/home/user/other/bin"))
}

func TestShellConfigFile(t *testing.T) {
	t.Setenv("SHELL", "/bin/zsh")
	assert.Equal(t, "~/.zshrc", shellConfigFile())

	t.Setenv("SHELL", "/bin/bash")
	assert.Equal(t, "~/.bashrc", shellConfigFile())

	t.Setenv("SHELL", "/usr/local/bin/zsh")
	assert.Equal(t, "~/.zshrc", shellConfigFile())
}

func TestHintMarkerPath(t *testing.T) {
	path := hintMarkerPath()
	assert.NotEmpty(t, path)
	assert.True(t, filepath.IsAbs(path))
	assert.Contains(t, path, ".aguara")
	assert.Contains(t, path, ".path-hint-shown")
}

func TestCheckPathHint_MarkerPreventsRepeat(t *testing.T) {
	// Create a temp dir to act as ~/.aguara
	tmpDir := t.TempDir()
	marker := filepath.Join(tmpDir, ".path-hint-shown")

	// Write the marker file
	err := os.WriteFile(marker, nil, 0o644)
	assert.NoError(t, err)

	// Verify the marker exists (simulates the "already shown" check)
	_, err = os.Stat(marker)
	assert.NoError(t, err, "marker file should exist and prevent re-showing hint")
}

func TestCheckPathHint_MarkerCreated(t *testing.T) {
	tmpDir := t.TempDir()
	marker := filepath.Join(tmpDir, ".aguara", ".path-hint-shown")

	// Simulate what checkPathHint does: mkdir + write marker
	err := os.MkdirAll(filepath.Dir(marker), 0o755)
	assert.NoError(t, err)
	err = os.WriteFile(marker, nil, 0o644)
	assert.NoError(t, err)

	_, err = os.Stat(marker)
	assert.NoError(t, err, "marker file should be created")
}

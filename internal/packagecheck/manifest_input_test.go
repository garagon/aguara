package packagecheck

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBoundedManifestReader(t *testing.T) {
	const limit = 64
	for _, size := range []int{0, limit - 1, limit, limit + 1, limit * 4} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			source := strings.NewReader(strings.Repeat("x", size))
			reader := boundedManifestReader(source, limit, "fixture")
			data, err := io.ReadAll(reader)
			if size <= limit {
				require.NoError(t, err)
				require.Len(t, data, size)
			} else {
				require.ErrorContains(t, err, "fixture input exceeds")
				consumed, err := source.Seek(0, io.SeekCurrent)
				require.NoError(t, err)
				require.EqualValues(t, limit+1, consumed)
				_, err = reader.Read(make([]byte, 1))
				require.Error(t, err, "overflow must remain an error")
			}
		})
	}
	t.Run("short lines cannot bypass total budget", func(t *testing.T) {
		scanner := bufio.NewScanner(boundedManifestReader(strings.NewReader(strings.Repeat("x\n", 40)), limit, "fixture"))
		for scanner.Scan() {
		}
		require.ErrorContains(t, scanner.Err(), "input exceeds")
	})
	t.Run("read errors survive", func(t *testing.T) {
		want := errors.New("interrupted")
		reader := io.MultiReader(strings.NewReader("x\n"), nugetFailingReader{err: want})
		scanner := bufio.NewScanner(boundedManifestReader(reader, limit, "fixture"))
		for scanner.Scan() {
		}
		require.ErrorIs(t, scanner.Err(), want)
	})
}

func TestOpenManifestRegularBoundary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest")
	require.NoError(t, os.WriteFile(path, []byte("small fixture"), 0o600))
	data, err := readManifest(path, "fixture")
	require.NoError(t, err)
	require.Equal(t, "small fixture", string(data))
	for _, invalid := range []string{dir, path + ".missing"} {
		file, err := openManifest(invalid, "fixture")
		require.Error(t, err)
		require.Nil(t, file)
	}
	t.Run("hardlinks remain regular files", func(t *testing.T) {
		link := filepath.Join(dir, "hardlink")
		if err := os.Link(path, link); err != nil {
			t.Skipf("hardlink unavailable: %v", err)
		}
		data, err := readManifest(link, "fixture")
		require.NoError(t, err)
		require.Equal(t, "small fixture", string(data))
	})
}

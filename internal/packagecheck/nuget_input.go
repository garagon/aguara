package packagecheck

import (
	"fmt"
	"io"
	"os"
)

// Match the scanner's default per-file limit. NuGet parsing must also enforce
// the limit when called directly, without directory discovery.
const maxNuGetManifestBytes int64 = 50 << 20

func readNuGetManifest(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("NuGet input must be a regular file, not a symlink or special file")
	}
	if info.Size() > maxNuGetManifestBytes {
		return nil, fmt.Errorf("NuGet input exceeds %d-byte limit", maxNuGetManifestBytes)
	}
	// Reject leaf symlinks at open time on Unix and verify the opened identity
	// before reading. This is not a snapshot of the discovery directory tree.
	f, err := os.OpenFile(path, os.O_RDONLY|manifestOpenFlags, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, fmt.Errorf("NuGet input changed while opening")
	}
	if opened.Size() > maxNuGetManifestBytes {
		return nil, fmt.Errorf("NuGet input exceeds %d-byte limit", maxNuGetManifestBytes)
	}
	return readNuGetBytes(f, maxNuGetManifestBytes)
}

func readNuGetBytes(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("NuGet input exceeds %d-byte limit", limit)
	}
	return data, nil
}

package packagecheck

import (
	"fmt"
	"io"
	"os"
)

// Guard the leaf at open time on Unix and verify the opened identity everywhere.
// Parent directories are not confined and the file contents are not a snapshot.
func openManifest(path, label string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s input must be a regular file, not a symlink or special file", label)
	}
	if info.Size() > maxManifestBytes {
		return nil, fmt.Errorf("%s input exceeds %d-byte limit", label, maxManifestBytes)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|manifestOpenFlags, 0)
	if err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	if err == nil && (!opened.Mode().IsRegular() || !os.SameFile(info, opened)) {
		err = fmt.Errorf("%s input changed while opening", label)
	}
	if err == nil && opened.Size() > maxManifestBytes {
		err = fmt.Errorf("%s input exceeds %d-byte limit", label, maxManifestBytes)
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func readManifest(path, label string) ([]byte, error) {
	f, err := openManifest(path, label)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return readBoundedManifestBytes(f, maxManifestBytes, label)
}

// Streaming parsers must distinguish an actual EOF from the byte budget ending.
// They retain their per-line limits and discard all refs on this reader's error.
func boundedManifestReader(r io.Reader, limit int64, label string) io.Reader {
	return &manifestLimitReader{reader: io.LimitReader(r, limit+1), remaining: limit, label: label}
}

type manifestLimitReader struct {
	reader    io.Reader
	remaining int64
	label     string
}

func (r *manifestLimitReader) Read(p []byte) (int, error) {
	if r.remaining < 0 {
		return 0, fmt.Errorf("%s input exceeds byte limit", r.label)
	}
	n, err := r.reader.Read(p)
	r.remaining -= int64(n)
	if r.remaining < 0 {
		return 0, fmt.Errorf("%s input exceeds byte limit", r.label)
	}
	return n, err
}

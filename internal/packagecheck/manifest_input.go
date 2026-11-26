package packagecheck

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/garagon/aguara/internal/safefile"
)

// openManifest opens a dependency file with the regular-file reader every
// untrusted input uses (safefile.OpenRegular): a symbolic link as the last
// path component, a named pipe, socket or device is refused before it is
// opened, the open never blocks on Unix, and a file replaced between the
// check and the open is refused. Parent directories are not confined and
// the file contents are not a snapshot.
func openManifest(path, label string) (*os.File, error) {
	f, info, err := safefile.OpenRegular(path, false)
	if err != nil {
		if errors.Is(err, safefile.ErrNotRegular) {
			return nil, &manifestNotRegularError{label: label, err: err}
		}
		return nil, err
	}
	if info.Size() > maxManifestBytes {
		_ = f.Close()
		return nil, fmt.Errorf("%s input exceeds %d-byte limit", label, maxManifestBytes)
	}
	return f, nil
}

// manifestNotRegularError keeps the dependency-file wording and still
// matches safefile.ErrNotRegular.
type manifestNotRegularError struct {
	label string
	err   error
}

func (e *manifestNotRegularError) Error() string {
	return e.label + " input must be a regular file, not a symlink or special file"
}

func (e *manifestNotRegularError) Unwrap() error { return e.err }

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

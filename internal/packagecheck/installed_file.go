package packagecheck

import (
	"io"

	"github.com/garagon/aguara/internal/safefile"
)

// ReadInstalledFilePrefix reads at most limit bytes of a file inside an
// installed environment (dist-info METADATA, .pth files). Symlinks are
// followed, because installers may link files from a cache, but the
// opened file must be a regular file: a FIFO or device is rejected
// without blocking (safefile.OpenRegular). truncated reports that the
// file is longer than limit. Installed trees from a cloned project are
// untrusted input, so callers must not read them with an unbounded
// os.ReadFile.
func ReadInstalledFilePrefix(path string, limit int64) (data []byte, truncated bool, err error) {
	f, _, err := safefile.OpenRegular(path, true)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = f.Close() }()
	data, err = io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > limit {
		return data[:limit], true, nil
	}
	return data, false, nil
}

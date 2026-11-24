package packagecheck

import (
	"fmt"
	"io"
	"os"
)

// ReadInstalledFilePrefix reads at most limit bytes of a file inside an
// installed environment (dist-info METADATA, .pth files). Symlinks are
// followed, because installers may link files from a cache, but the
// opened file must be a regular file: a FIFO or device is rejected
// without blocking. truncated reports that the file is longer than
// limit. Installed trees from a cloned project are untrusted input, so
// callers must not read them with an unbounded os.ReadFile.
func ReadInstalledFilePrefix(path string, limit int64) (data []byte, truncated bool, err error) {
	f, err := os.OpenFile(path, os.O_RDONLY|installedOpenFlags, 0)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("%s is not a regular file", path)
	}
	data, err = io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > limit {
		return data[:limit], true, nil
	}
	return data, false, nil
}

package safefile

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
)

// ErrNotRegular is matched by errors.Is when a file to be read is not a
// regular file: a named pipe, socket, device, directory or symbolic link.
var ErrNotRegular = errors.New("not a regular file")

// ErrTooLarge is matched by errors.Is when a file is larger than the read
// limit.
var ErrTooLarge = errors.New("file too large")

// NotRegularError reports a file that cannot be read as file content.
type NotRegularError struct {
	Path string
	Mode os.FileMode
}

func (e *NotRegularError) Error() string {
	return fmt.Sprintf("%s is a %s, not a regular file", e.Path, DescribeMode(e.Mode))
}

// Is reports ErrNotRegular.
func (e *NotRegularError) Is(target error) bool { return target == ErrNotRegular }

// TooLargeError reports a file over the read limit.
type TooLargeError struct {
	Path  string
	Limit int64
}

func (e *TooLargeError) Error() string {
	return fmt.Sprintf("%s exceeds %d-byte limit", e.Path, e.Limit)
}

// Is reports ErrTooLarge.
func (e *TooLargeError) Is(target error) bool { return target == ErrTooLarge }

// DescribeMode names the kind of file mode describes, for messages.
func DescribeMode(mode os.FileMode) string {
	switch {
	case mode.IsRegular():
		return "regular file"
	case mode&os.ModeSymlink != 0:
		return "symbolic link"
	case mode&os.ModeNamedPipe != 0:
		return "named pipe"
	case mode&os.ModeSocket != 0:
		return "socket"
	case mode&os.ModeDevice != 0:
		return "device"
	case mode.IsDir():
		return "directory"
	default:
		return "irregular file"
	}
}

// OpenRegular opens path for reading only when it is a regular file.
//
// The file type is checked before the open, so a named pipe, socket or
// device found there is never opened, and again on the opened descriptor,
// so a file replaced between the two steps is rejected instead of read.
// On Unix the open is non-blocking (a named pipe swapped in cannot stall
// it) and, unless followSymlink is set, refuses a symbolic link as the last
// path component. Every platform also checks that the opened file is the
// one that was inspected.
//
// The check covers the last path component only: parent directories are
// not confined, and the content is not a snapshot (a regular file can
// still be written to while it is read).
func OpenRegular(path string, followSymlink bool) (*os.File, os.FileInfo, error) {
	stat := os.Lstat
	flags := os.O_RDONLY | openNonBlock
	if followSymlink {
		stat = os.Stat
	} else {
		flags |= openNoFollow
	}
	info, err := stat(path)
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, &NotRegularError{Path: path, Mode: info.Mode()}
	}
	f, err := os.OpenFile(path, flags, 0)
	if err != nil {
		return nil, nil, err
	}
	opened, err := f.Stat()
	if err == nil && !opened.Mode().IsRegular() {
		err = &NotRegularError{Path: path, Mode: opened.Mode()}
	}
	if err == nil && !os.SameFile(info, opened) {
		err = fmt.Errorf("%s changed while it was opened", path)
	}
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	return f, opened, nil
}

// ReadRegular reads a regular file of at most limit bytes (see
// OpenRegular). The limit holds whatever the file's reported size: at most
// limit+1 bytes are read, and a longer file is a *TooLargeError.
func ReadRegular(path string, followSymlink bool, limit int64) ([]byte, error) {
	f, info, err := OpenRegular(path, followSymlink)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if info.Size() > limit {
		return nil, &TooLargeError{Path: path, Limit: limit}
	}
	return ReadLimited(f, path, limit)
}

// ReadLimited reads r to the end, failing with a *TooLargeError once more
// than limit bytes arrive. path only labels the error.
func ReadLimited(r io.Reader, path string, limit int64) ([]byte, error) {
	readLimit := limit
	if readLimit < math.MaxInt64 {
		readLimit++
	}
	data, err := io.ReadAll(io.LimitReader(r, readLimit))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, &TooLargeError{Path: path, Limit: limit}
	}
	return data, nil
}

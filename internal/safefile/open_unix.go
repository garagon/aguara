//go:build unix

package safefile

import "golang.org/x/sys/unix"

// A non-blocking open returns at once for a named pipe without a writer;
// regular-file reads are unaffected by the flag.
const (
	openNonBlock = unix.O_NONBLOCK
	openNoFollow = unix.O_NOFOLLOW
)

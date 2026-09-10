//go:build unix

package packagecheck

import "golang.org/x/sys/unix"

const manifestOpenFlags = unix.O_NONBLOCK | unix.O_NOFOLLOW

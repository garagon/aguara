//go:build unix

package packagecheck

import "golang.org/x/sys/unix"

const manifestOpenFlags = unix.O_NONBLOCK | unix.O_NOFOLLOW

// installedOpenFlags never blocks on a FIFO or device but follows
// symlinks: installers such as uv can link files into site-packages.
const installedOpenFlags = unix.O_NONBLOCK

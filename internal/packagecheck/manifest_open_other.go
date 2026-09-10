//go:build !unix

package packagecheck

// Non-Unix platforms retain the metadata checks and bounded read, but do not
// provide the Unix atomic leaf-symlink rejection at open time.
const manifestOpenFlags = 0

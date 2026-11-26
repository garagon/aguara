//go:build !unix

package safefile

// Other platforms have no non-blocking or no-follow open flag. Named pipes
// and sockets do not appear in ordinary Windows directories, and the type
// and identity checks in OpenRegular still reject a device or a replaced
// file before anything is read.
const (
	openNonBlock = 0
	openNoFollow = 0
)

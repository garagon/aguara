package packagecheck

import (
	"io"
)

// Match the scanner's default per-file limit. NuGet parsing must also enforce
// the limit when called directly, without directory discovery.
const maxNuGetManifestBytes int64 = maxManifestBytes

func readNuGetManifest(path string) ([]byte, error) {
	return readManifest(path, "NuGet")
}

func readNuGetBytes(r io.Reader, limit int64) ([]byte, error) {
	return readBoundedManifestBytes(r, limit, "NuGet")
}

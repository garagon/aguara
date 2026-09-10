package packagecheck

import (
	"fmt"
	"io"
)

const maxManifestBytes int64 = 50 << 20

func readBoundedManifestBytes(r io.Reader, limit int64, label string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s input exceeds %d-byte limit", label, limit)
	}
	return data, nil
}

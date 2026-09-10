package aguara_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/garagon/aguara"
)

func TestPublicDirectorySizeLimit(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "large.md"), []byte("123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := aguara.NewScanner(aguara.WithWorkers(1), aguara.WithMaxFileSize(8))
	if err != nil {
		t.Fatal(err)
	}
	for _, scan := range []func() (*aguara.ScanResult, error){
		func() (*aguara.ScanResult, error) { return s.Scan(ctx, dir) },
		func() (*aguara.ScanResult, error) {
			return aguara.Scan(ctx, dir, aguara.WithWorkers(1), aguara.WithMaxFileSize(8))
		},
	} {
		result, err := scan()
		if result != nil || !errors.Is(err, aguara.ErrIncompleteScan) || !strings.Contains(err.Error(), "8-byte limit") {
			t.Fatalf("oversize directory: result=%v err=%v", result, err)
		}
	}
	// Explicit caller exclusions still define the intended scan surface.
	result, err := aguara.Scan(ctx, dir, aguara.WithWorkers(1), aguara.WithMaxFileSize(8), aguara.WithIgnorePatterns([]string{"large.md"}))
	if err != nil || result.FilesScanned != 0 {
		t.Fatalf("caller exclusion: result=%v err=%v", result, err)
	}
}

package scanner

import (
	"errors"
	"io"
	"math"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecursiveSizeExclusionsUseNativePathSeparators(t *testing.T) {
	for _, input := range []string{
		filepath.Join("excluded", "large.md"),
		filepath.Join("excluded", "nested", "large.md"),
	} {
		if !matchGlob("excluded/**", input) {
			t.Fatalf("recursive exclusion missed native path %q", input)
		}
	}
	td := &TargetDiscovery{IgnorePatterns: []string{"excluded/**"}}
	if !td.isIgnoredSubtree(filepath.Join("excluded", "nested")) {
		t.Fatal("excluded subtree not recognized")
	}
	if filepath.Separator == '/' && matchGlob("excluded/**", `excluded\large.md`) {
		t.Fatal("literal Unix backslash reinterpreted as a directory separator")
	}
}

func TestReadTargetBytesLimit(t *testing.T) {
	for _, size := range []int{0, 7, 8, 9, 32} {
		input := strings.NewReader(strings.Repeat("x", size))
		data, err := readTargetBytes(input, 8)
		if size <= 8 {
			if err != nil || len(data) != size {
				t.Fatalf("size %d: data=%q err=%v", size, data, err)
			}
		} else {
			var sizeErr *fileSizeError
			if data != nil || !errors.As(err, &sizeErr) || sizeErr.limit != 8 {
				t.Fatalf("overflow returned data=%q err=%v", data, err)
			}
			if input.Len() != size-9 {
				t.Fatalf("consumed beyond bounded lookahead: %d", size-input.Len())
			}
		}
	}
	data, err := readTargetBytes(strings.NewReader("ok"), math.MaxInt64)
	if err != nil || string(data) != "ok" {
		t.Fatalf("MaxInt64 limit overflowed: data=%q err=%v", data, err)
	}
}

type targetReadError struct{ err error }

func (r targetReadError) Read([]byte) (int, error) { return 0, r.err }

func TestReadTargetBytesDiscardsPartialData(t *testing.T) {
	want := errors.New("synthetic source error")
	data, err := readTargetBytes(io.MultiReader(strings.NewReader("prefix"), targetReadError{want}), 8)
	if data != nil || !errors.Is(err, want) {
		t.Fatalf("read error returned data=%q err=%v", data, err)
	}
}

package types

import "testing"

// Which skipped entries may stand for content no scan read, the question
// audit triage asks. A path an ignore pattern excludes and a file the run
// writes are left out on purpose; everything else was not read although an
// agent could read it.
func TestSkippedFileHidesContent(t *testing.T) {
	for _, tc := range []struct {
		entry SkippedFile
		hides bool
	}{
		{SkippedFile{Kind: SkippedSymlink, Resolves: LinkInside}, false},
		{SkippedFile{Kind: SkippedSymlink, Resolves: LinkExcluded}, true},
		{SkippedFile{Kind: SkippedSymlink, Resolves: LinkOutside}, true},
		{SkippedFile{Kind: SkippedSymlink, Resolves: LinkDangling}, true},
		{SkippedFile{Kind: SkippedNamedPipe}, true},
		{SkippedFile{Kind: SkippedSocket}, true},
		{SkippedFile{Kind: SkippedDevice}, true},
		{SkippedFile{Kind: SkippedIrregular}, true},
		{SkippedFile{Kind: SkippedInSkippedDir}, true},
		{SkippedFile{Kind: SkippedIgnored}, false},
		{SkippedFile{Kind: SkippedOutputFile}, false},
	} {
		if got := tc.entry.HidesContent(); got != tc.hides {
			t.Errorf("%s/%s: HidesContent() = %v, want %v", tc.entry.Kind, tc.entry.Resolves, got, tc.hides)
		}
	}
}

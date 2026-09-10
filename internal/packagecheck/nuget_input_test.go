package packagecheck

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/intel"
)

func TestNuGetRejectsSymlinkInputs(t *testing.T) {
	for _, source := range []string{"csproj", "fsproj", "vbproj", "packages.lock.json"} {
		t.Run(source, func(t *testing.T) {
			outside := filepath.Join(t.TempDir(), "manifest")
			content := `<Project><ItemGroup><PackageReference Include="Example" Version="1.0.0" /></ItemGroup></Project>`
			if source == "packages.lock.json" {
				content = `{"dependencies":{"net8.0":{"Example":{"resolved":"1.0.0"}}}}`
			}
			writeFile(t, outside, content)
			if refs, err := ParseNuGet(Target{Path: outside, Source: source}); err != nil || len(refs) != 1 {
				t.Fatalf("regular-file control: refs=%v err=%v", refs, err)
			}
			path := filepath.Join(t.TempDir(), "linked."+source)
			if err := os.Symlink(outside, path); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}
			refs, err := ParseNuGet(Target{Path: path, Source: source})
			if err == nil || len(refs) != 0 {
				t.Fatalf("symlink accepted: refs=%v err=%v", refs, err)
			}
		})
	}
}

func TestNuGetDiscoveryReportsSymlinks(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "project")
	writeFile(t, outside, "<Project />")
	for _, name := range []string{"linked.csproj", "linked.fsproj", "linked.vbproj", "packages.lock.json", "dangling.csproj"} {
		target := outside
		if strings.HasPrefix(name, "dangling") {
			target += ".missing"
		}
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
	}
	writeFile(t, filepath.Join(dir, "Real.CSPROJ"), "<Project />")
	targets, err := Discover(dir, []string{intel.EcosystemNuGet})
	if err != nil || len(targets) != 6 {
		t.Fatalf("unexpected targets: %+v err=%v", targets, err)
	}
	for _, target := range targets {
		refs, err := ParseNuGet(target)
		if filepath.Base(target.Path) == "Real.CSPROJ" {
			if err != nil {
				t.Fatalf("regular project: %v", err)
			}
		} else if err == nil || len(refs) != 0 {
			t.Fatalf("linked candidate accepted: %+v refs=%v err=%v", target, refs, err)
		}
	}
	runner := &Runner{Matcher: intel.NewMatcher(intel.Snapshot{})}
	if result, err := runner.Run(targets); err == nil || result != nil {
		t.Fatalf("unsafe discovery returned success: result=%+v err=%v", result, err)
	}
}

func TestNuGetRunnerRejectsOversizeWithoutPartialResults(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "Good.csproj")
	writeFile(t, good, `<Project><ItemGroup><PackageReference Include="Example" Version="1.0.0" /></ItemGroup></Project>`)
	bad := filepath.Join(dir, "packages.lock.json")
	f, err := os.Create(bad)
	if err != nil {
		t.Fatal(err)
	}
	sizeErr := f.Truncate(maxNuGetManifestBytes + 1)
	closeErr := f.Close()
	if sizeErr != nil || closeErr != nil {
		t.Fatalf("sparse fixture: %v %v", sizeErr, closeErr)
	}
	runner := &Runner{Matcher: intel.NewMatcher(intel.Snapshot{})}
	result, err := runner.Run([]Target{
		{Ecosystem: intel.EcosystemNuGet, Path: good, Source: "csproj"},
		{Ecosystem: intel.EcosystemNuGet, Path: bad, Source: "packages.lock.json"},
	})
	if result != nil || err == nil || !strings.Contains(err.Error(), bad) || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("expected contextual error without partial result: result=%+v err=%v", result, err)
	}
}

type nugetFailingReader struct{ err error }

func (r nugetFailingReader) Read([]byte) (int, error) { return 0, r.err }

func TestReadNuGetBytesDiscardsPartialReadOnError(t *testing.T) {
	want := errors.New("read interrupted")
	input := io.MultiReader(strings.NewReader("<Project>"), nugetFailingReader{err: want})
	data, err := readNuGetBytes(input, 64)
	if data != nil || !errors.Is(err, want) {
		t.Fatalf("partial read returned: data=%q err=%v", data, err)
	}
}

func TestNuGetRejectsNonRegularAndOversizedInputs(t *testing.T) {
	for _, source := range []string{"csproj", "fsproj", "vbproj", "packages.lock.json"} {
		t.Run(source, func(t *testing.T) {
			dir := t.TempDir()
			if _, err := ParseNuGet(Target{Path: dir, Source: source}); err == nil {
				t.Fatal("accepted directory")
			}
			path := filepath.Join(dir, "large")
			f, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			err = f.Truncate(maxNuGetManifestBytes + 1)
			closeErr := f.Close()
			if err != nil || closeErr != nil {
				t.Fatalf("create sparse fixture: %v %v", err, closeErr)
			}
			refs, err := ParseNuGet(Target{Path: path, Source: source})
			if err == nil || !strings.Contains(err.Error(), "limit") || len(refs) != 0 {
				t.Fatalf("oversize input: refs=%v err=%v", refs, err)
			}
		})
	}
}

func TestReadNuGetBytesBoundaries(t *testing.T) {
	const limit = 64
	for _, size := range []int{0, limit - 1, limit, limit + 1, limit * 100} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			source := strings.NewReader(strings.Repeat(" ", size))
			got, err := readNuGetBytes(source, limit)
			if size > limit {
				if err == nil || got != nil {
					t.Fatalf("overflow returned data: len=%d err=%v", len(got), err)
				}
				read, _ := source.Seek(0, io.SeekCurrent)
				if read != limit+1 {
					t.Fatalf("read %d bytes beyond bounded request", read)
				}
			} else if err != nil || len(got) != size {
				t.Fatalf("valid boundary: len=%d err=%v", len(got), err)
			}
		})
	}
}

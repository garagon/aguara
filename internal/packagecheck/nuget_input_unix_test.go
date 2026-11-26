//go:build unix

package packagecheck

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/garagon/aguara/internal/intel"
	"github.com/garagon/aguara/internal/safefile"
	"golang.org/x/sys/unix"
)

func TestNuGetRejectsFIFO(t *testing.T) {
	for _, source := range []string{"csproj", "fsproj", "vbproj", "packages.lock.json"} {
		t.Run(source, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input."+source)
			if err := unix.Mkfifo(path, 0600); err != nil {
				t.Fatal(err)
			}
			refs, err := ParseNuGet(Target{Path: path, Source: source})
			if err == nil || len(refs) != 0 {
				t.Fatalf("FIFO accepted: refs=%v err=%v", refs, err)
			}
			// A FIFO swapped in after the type check opens without
			// waiting and fails the check on the opened file; the shared
			// reader's own tests cover that (internal/safefile).
			if !errors.Is(err, safefile.ErrNotRegular) {
				t.Fatalf("FIFO error does not match safefile.ErrNotRegular: %v", err)
			}
		})
	}
}

func TestNuGetUnixOpenRejectsLeafSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	writeFile(t, target, "<Project />")
	link := filepath.Join(dir, "linked.csproj")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	f, err := openManifest(link, "NuGet")
	if f != nil {
		_ = f.Close()
	}
	if err == nil {
		t.Fatal("a leaf symlink was opened")
	}
}

func TestNuGetDiscoveryReportsFIFO(t *testing.T) {
	for _, name := range []string{"App.csproj", "App.fsproj", "App.vbproj", "packages.lock.json"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := unix.Mkfifo(filepath.Join(dir, name), 0600); err != nil {
				t.Fatal(err)
			}
			targets, err := Discover(dir, []string{intel.EcosystemNuGet})
			if err != nil || len(targets) != 1 {
				t.Fatalf("special-file target hidden: targets=%+v err=%v", targets, err)
			}
			runner := &Runner{Matcher: intel.NewMatcher(intel.Snapshot{})}
			if result, err := runner.Run(targets); err == nil || result != nil {
				t.Fatalf("FIFO produced success: result=%+v err=%v", result, err)
			}
		})
	}
}

func TestNuGetRejectsFIFOParent(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "not-a-directory")
	if err := unix.Mkfifo(parent, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseNuGet(Target{Path: filepath.Join(parent, "App.csproj"), Source: "csproj"}); err == nil {
		t.Fatal("accepted FIFO parent")
	}
}

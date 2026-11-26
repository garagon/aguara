//go:build unix

package packagecheck

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/garagon/aguara/internal/intel"
)

// Each read position of the package checks goes through the shared
// regular-file reader: a named pipe, a link to an endless device, a link
// to a regular file and an oversized file are refused without blocking,
// wherever the file sits. The positions are the manifests of the discovery
// walk, pip files under names discovery does not read, requirements
// includes, a go.mod beside a go.sum, a Directory.Packages.props above a
// .NET project, and files inside an installed environment.
func TestPackageInputsRefuseSpecialFiles(t *testing.T) {
	type input struct {
		name   string
		target string // the file replaced by the special input
		setup  func(dir string)
		read   func(dir string) (refused bool)
	}
	unread := func(dir, name string) bool {
		found, err := DiscoverUnevaluated(dir, nil)
		if err != nil {
			return true
		}
		for _, m := range found.Manifests {
			if filepath.Base(m.Path) == name {
				return m.Unreadable
			}
		}
		for _, u := range found.Unsupported {
			if filepath.Base(u.Path) == name {
				return false
			}
		}
		// Not claimed at all (a pip-name or conda file whose content
		// cannot be read): nothing was read from it.
		return true
	}
	var inputs []input
	for _, name := range []string{"package.json", "composer.json", "pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "requirements.in", "Cargo.toml", "Gemfile", "environment.yml", "dev-reqs.txt"} {
		inputs = append(inputs, input{name: "discovery " + name, target: name, read: func(dir string) bool { return unread(dir, name) }})
	}
	inputs = append(inputs,
		input{
			name: "requirements include", target: "inc.txt",
			setup: func(dir string) { writeFile(t, filepath.Join(dir, "requirements.txt"), "-r inc.txt\n") },
			read: func(dir string) bool {
				_, err := ParseRequirements(Target{Ecosystem: intel.EcosystemPyPI, Path: filepath.Join(dir, "requirements.txt"), Source: "requirements.txt", Root: dir})
				return err != nil
			},
		},
		input{
			name: "requirements.in include", target: "base.in",
			setup: func(dir string) { writeFile(t, filepath.Join(dir, "requirements.in"), "flask\n-r base.in\n") },
			read:  func(dir string) bool { return unread(dir, "requirements.in") },
		},
		input{
			name: "go.mod beside go.sum", target: "go.mod",
			setup: func(dir string) {
				writeFile(t, filepath.Join(dir, "go.sum"), "golang.org/x/text v0.3.7 h1:olpwvP2KacW1ZWvsR7uQhoyTYvKAupfQrRGBFM352Gk=\n")
			},
			read: func(dir string) bool {
				_, err := ParseGo(Target{Ecosystem: intel.EcosystemGo, Path: filepath.Join(dir, "go.sum"), Source: "go.sum"})
				return err != nil
			},
		},
		input{
			name: "Directory.Packages.props", target: "Directory.Packages.props",
			setup: func(dir string) {
				writeFile(t, filepath.Join(dir, "app.csproj"), `<Project><ItemGroup><PackageReference Include="A" /></ItemGroup></Project>`)
			},
			read: func(dir string) bool {
				_, err := ParseNuGet(Target{Ecosystem: intel.EcosystemNuGet, Path: filepath.Join(dir, "app.csproj"), Source: "csproj", Root: dir})
				return err != nil
			},
		},
	)

	special := map[string]func(t *testing.T, path string){
		"named pipe": func(t *testing.T, path string) {
			if err := unix.Mkfifo(path, 0o600); err != nil {
				t.Skipf("mkfifo unavailable: %v", err)
			}
		},
		"link to /dev/zero": func(t *testing.T, path string) {
			require.NoError(t, os.Symlink("/dev/zero", path))
		},
		"link to a regular file": func(t *testing.T, path string) {
			real := path + ".real"
			require.NoError(t, os.WriteFile(real, []byte("{}\n"), 0o600))
			require.NoError(t, os.Symlink(real, path))
		},
		"oversized": func(t *testing.T, path string) {
			f, err := os.Create(path)
			require.NoError(t, err)
			require.NoError(t, f.Truncate(maxManifestBytes+1))
			require.NoError(t, f.Close())
		},
	}
	for _, in := range inputs {
		for kind, create := range special {
			t.Run(in.name+"/"+kind, func(t *testing.T) {
				dir := t.TempDir()
				if in.setup != nil {
					in.setup(dir)
				}
				create(t, filepath.Join(dir, in.target))
				done := make(chan bool, 1)
				go func() { done <- in.read(dir) }()
				select {
				case refused := <-done:
					require.True(t, refused, "%s was read", in.target)
				case <-time.After(10 * time.Second):
					t.Fatalf("reading %s blocked", in.target)
				}
			})
		}
	}

	// Files inside an installed environment follow links, but never block
	// on a named pipe and never read a device.
	dir := t.TempDir()
	fifo := filepath.Join(dir, "METADATA")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	zero := filepath.Join(dir, "x.pth")
	require.NoError(t, os.Symlink("/dev/zero", zero))
	for _, path := range []string{fifo, zero} {
		done := make(chan error, 1)
		go func() { _, _, err := ReadInstalledFilePrefix(path, 1<<20); done <- err }()
		select {
		case err := <-done:
			require.ErrorContains(t, err, "not a regular file", path)
		case <-time.After(10 * time.Second):
			t.Fatalf("reading %s blocked", path)
		}
	}
}

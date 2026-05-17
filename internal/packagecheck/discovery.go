package packagecheck

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/garagon/aguara/internal/intel"
)

// defaultSkipDirs are directories Discover never descends into.
// node_modules is intentionally skipped here even when Discover is
// asked for the npm ecosystem in the future; nested dependencies of
// dependencies are not what the user is asking about. .git / vendor
// / .aguara round out the "never read" set.
var defaultSkipDirs = map[string]bool{
	".git":         true,
	"vendor":       true,
	"node_modules": true,
	".aguara":      true,
}

// Discover walks root and returns one Target per lockfile / discovery
// anchor for every requested ecosystem. Currently only Go is
// implemented (go.sum primary, go.mod fallback when the directory
// has go.mod but no go.sum); future ecosystems hook in by extending
// the per-directory switch in walkDir.
//
// When `ecosystems` is empty or nil, Discover scans for every
// ecosystem packagecheck knows about. Callers that want to scope
// to a single ecosystem pass e.g. []string{intel.EcosystemGo}.
//
// Discovery is deterministic (filepath.WalkDir orders alphabetically)
// and offline. Errors from filepath.WalkDir surface as-is so the
// caller can distinguish "no go.sum found" (returns empty slice,
// no error) from "permission denied reading root" (returns error).
func Discover(root string, ecosystems []string) ([]Target, error) {
	want := map[string]bool{}
	if len(ecosystems) == 0 {
		want[intel.EcosystemGo] = true
	} else {
		for _, eco := range ecosystems {
			want[eco] = true
		}
	}

	var targets []Target
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// A permission error on a nested directory must not
			// abort the whole walk; logging would be noise.
			// Surface only the root-level error via the caller's
			// pre-walk Stat (handled in the runner / CLI layer).
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		if path != root && defaultSkipDirs[d.Name()] {
			return fs.SkipDir
		}
		if want[intel.EcosystemGo] {
			if t := pickGoTarget(path); t != nil {
				targets = append(targets, *t)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return targets, nil
}

// pickGoTarget returns a Target for a Go module rooted at dir, or
// nil when no go.sum / go.mod is present. go.sum wins when both
// exist because it carries the resolved version set the matcher
// needs; go.mod is the fallback for projects with `require` lines
// but no checked-in go.sum (libraries that delegate locking to the
// downstream consumer).
func pickGoTarget(dir string) *Target {
	if statRegular(filepath.Join(dir, "go.sum")) {
		return &Target{
			Ecosystem: intel.EcosystemGo,
			Path:      filepath.Join(dir, "go.sum"),
			Source:    "go.sum",
		}
	}
	if statRegular(filepath.Join(dir, "go.mod")) {
		return &Target{
			Ecosystem: intel.EcosystemGo,
			Path:      filepath.Join(dir, "go.mod"),
			Source:    "go.mod",
		}
	}
	return nil
}

func statRegular(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

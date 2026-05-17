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

// lockfilePicker pairs an ecosystem with the function that probes
// a directory for the matching lockfile (or fallback). One picker
// per ecosystem keeps Discover linear in `len(lockfilePickers) *
// dirs walked`; adding a new ecosystem is one entry in the slice
// plus the picker implementation.
type lockfilePicker struct {
	ecosystem string
	pick      func(dir string) *Target
}

var lockfilePickers = []lockfilePicker{
	{intel.EcosystemGo, pickGoTarget},
	{intel.EcosystemCargo, pickCargoTarget},
	{intel.EcosystemPackagist, pickComposerTarget},
	{intel.EcosystemRubyGems, pickRubyTarget},
}

// Discover walks root and returns one Target per lockfile / discovery
// anchor for every requested ecosystem.
//
// When `ecosystems` is empty or nil, Discover scans for every
// ecosystem packagecheck knows about. Callers that want to scope
// to a single ecosystem pass e.g. []string{intel.EcosystemGo}.
//
// Discovery is deterministic (filepath.WalkDir orders alphabetically)
// and offline. Errors from filepath.WalkDir surface as-is so the
// caller can distinguish "no lockfile found" (returns empty slice,
// no error) from "permission denied reading root" (returns error).
func Discover(root string, ecosystems []string) ([]Target, error) {
	want := map[string]bool{}
	if len(ecosystems) == 0 {
		for _, p := range lockfilePickers {
			want[p.ecosystem] = true
		}
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
		for _, p := range lockfilePickers {
			if !want[p.ecosystem] {
				continue
			}
			if t := p.pick(path); t != nil {
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

// pickCargoTarget returns a Target for a Cargo workspace rooted
// at dir, or nil when no Cargo.lock is present. Cargo.toml-only
// directories are intentionally skipped: without a lockfile the
// resolved version set is whatever `cargo update` would produce
// today, which the offline parser cannot determine.
func pickCargoTarget(dir string) *Target {
	if statRegular(filepath.Join(dir, "Cargo.lock")) {
		return &Target{
			Ecosystem: intel.EcosystemCargo,
			Path:      filepath.Join(dir, "Cargo.lock"),
			Source:    "Cargo.lock",
		}
	}
	return nil
}

// pickComposerTarget returns a Target for a PHP project rooted at
// dir, or nil when no composer.lock is present. composer.json
// alone (no lockfile) is skipped for the same reason as Cargo.toml
// without Cargo.lock.
func pickComposerTarget(dir string) *Target {
	if statRegular(filepath.Join(dir, "composer.lock")) {
		return &Target{
			Ecosystem: intel.EcosystemPackagist,
			Path:      filepath.Join(dir, "composer.lock"),
			Source:    "composer.lock",
		}
	}
	return nil
}

// pickRubyTarget returns a Target for a Ruby/Bundler project
// rooted at dir, or nil when no Gemfile.lock is present.
func pickRubyTarget(dir string) *Target {
	if statRegular(filepath.Join(dir, "Gemfile.lock")) {
		return &Target{
			Ecosystem: intel.EcosystemRubyGems,
			Path:      filepath.Join(dir, "Gemfile.lock"),
			Source:    "Gemfile.lock",
		}
	}
	return nil
}

func statRegular(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

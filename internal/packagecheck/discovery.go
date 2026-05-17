package packagecheck

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/garagon/aguara/internal/intel"
)

// defaultSkipDirs are directories Discover never descends into.
// node_modules is intentionally skipped here even when Discover is
// asked for the npm ecosystem in the future; nested dependencies of
// dependencies are not what the user is asking about. .git / vendor
// / .aguara round out the original "never read" set.
//
// PR #4 added the four build-output directories Maven / Gradle /
// .NET emit by default. `target/` (Maven build output), `bin/` and
// `obj/` (MSBuild output: stamped .csproj/.fsproj/.vbproj copies,
// generated project.assets.json), and `.gradle/` (Gradle cache)
// would otherwise drag stale or generated manifests into the
// discovery output; skipping them keeps the user-visible
// `ecosystems[]` aligned with what the developer actually
// committed.
var defaultSkipDirs = map[string]bool{
	".git":         true,
	"vendor":       true,
	"node_modules": true,
	".aguara":      true,
	"target":       true,
	"bin":          true,
	"obj":          true,
	".gradle":      true,
}

// lockfilePicker pairs an ecosystem with the function that probes
// a directory for matching lockfiles. PR #4 widened the return
// type from *Target to []Target because Maven and NuGet routinely
// emit multiple lockfiles per directory (a Maven+Gradle project
// has both pom.xml and gradle.lockfile; a .NET project directory
// can host packages.lock.json plus one or more .csproj/.fsproj/
// .vbproj files). Pickers for single-file ecosystems return a
// one-element slice. Empty / nil = nothing of interest in this
// directory.
//
// Adding a new ecosystem is one entry in the slice plus the
// picker implementation.
type lockfilePicker struct {
	ecosystem string
	pick      func(dir string) []Target
}

var lockfilePickers = []lockfilePicker{
	{intel.EcosystemGo, pickGoTarget},
	{intel.EcosystemCargo, pickCargoTarget},
	{intel.EcosystemPackagist, pickComposerTarget},
	{intel.EcosystemRubyGems, pickRubyTarget},
	{intel.EcosystemMaven, pickMavenTargets},
	{intel.EcosystemNuGet, pickNuGetTargets},
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
			targets = append(targets, p.pick(path)...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return targets, nil
}

// pickGoTarget returns a Target for a Go module rooted at dir, or
// an empty slice when no go.sum / go.mod is present. go.sum wins
// when both exist because it carries the resolved version set the
// matcher needs; go.mod is the fallback for projects with
// `require` lines but no checked-in go.sum (libraries that delegate
// locking to the downstream consumer).
func pickGoTarget(dir string) []Target {
	if statRegular(filepath.Join(dir, "go.sum")) {
		return []Target{{
			Ecosystem: intel.EcosystemGo,
			Path:      filepath.Join(dir, "go.sum"),
			Source:    "go.sum",
		}}
	}
	if statRegular(filepath.Join(dir, "go.mod")) {
		return []Target{{
			Ecosystem: intel.EcosystemGo,
			Path:      filepath.Join(dir, "go.mod"),
			Source:    "go.mod",
		}}
	}
	return nil
}

// pickCargoTarget returns a Target for a Cargo workspace rooted
// at dir, or nil when no Cargo.lock is present. Cargo.toml-only
// directories are intentionally skipped: without a lockfile the
// resolved version set is whatever `cargo update` would produce
// today, which the offline parser cannot determine.
func pickCargoTarget(dir string) []Target {
	if statRegular(filepath.Join(dir, "Cargo.lock")) {
		return []Target{{
			Ecosystem: intel.EcosystemCargo,
			Path:      filepath.Join(dir, "Cargo.lock"),
			Source:    "Cargo.lock",
		}}
	}
	return nil
}

// pickComposerTarget returns a Target for a PHP project rooted at
// dir, or nil when no composer.lock is present. composer.json
// alone (no lockfile) is skipped for the same reason as Cargo.toml
// without Cargo.lock.
func pickComposerTarget(dir string) []Target {
	if statRegular(filepath.Join(dir, "composer.lock")) {
		return []Target{{
			Ecosystem: intel.EcosystemPackagist,
			Path:      filepath.Join(dir, "composer.lock"),
			Source:    "composer.lock",
		}}
	}
	return nil
}

// pickRubyTarget returns a Target for a Ruby/Bundler project
// rooted at dir, or nil when no Gemfile.lock is present.
func pickRubyTarget(dir string) []Target {
	if statRegular(filepath.Join(dir, "Gemfile.lock")) {
		return []Target{{
			Ecosystem: intel.EcosystemRubyGems,
			Path:      filepath.Join(dir, "Gemfile.lock"),
			Source:    "Gemfile.lock",
		}}
	}
	return nil
}

// pickMavenTargets returns every Maven-family manifest in dir:
//
//   - pom.xml          (Maven proper)
//   - gradle.lockfile  (Gradle single-lockfile mode, project root)
//   - *.lockfile inside dir when dir basename is "dependency-locks"
//     and its parent is "gradle" (Gradle per-configuration mode)
//
// Each match becomes its own Target so a polyglot project with
// both Maven and Gradle locks shows every manifest in the
// ecosystems[] output. Source labels: "pom.xml" for Maven,
// "gradle.lockfile" for both Gradle modes (they share the parser).
func pickMavenTargets(dir string) []Target {
	var out []Target
	if statRegular(filepath.Join(dir, "pom.xml")) {
		out = append(out, Target{
			Ecosystem: intel.EcosystemMaven,
			Path:      filepath.Join(dir, "pom.xml"),
			Source:    "pom.xml",
		})
	}
	if statRegular(filepath.Join(dir, "gradle.lockfile")) {
		out = append(out, Target{
			Ecosystem: intel.EcosystemMaven,
			Path:      filepath.Join(dir, "gradle.lockfile"),
			Source:    "gradle.lockfile",
		})
	}
	// Per-configuration lockfiles live in `gradle/dependency-locks/`.
	// We detect that exact path by checking the current directory's
	// basename plus its parent's basename to keep the picker from
	// firing on a stray `*.lockfile` somewhere else in the tree.
	parent := filepath.Base(filepath.Dir(dir))
	base := filepath.Base(dir)
	if base == "dependency-locks" && parent == "gradle" {
		entries, err := os.ReadDir(dir)
		if err == nil {
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				if !strings.HasSuffix(e.Name(), ".lockfile") {
					continue
				}
				out = append(out, Target{
					Ecosystem: intel.EcosystemMaven,
					Path:      filepath.Join(dir, e.Name()),
					Source:    "gradle.lockfile",
				})
			}
		}
	}
	return out
}

// pickNuGetTargets returns every NuGet manifest in dir:
//
//   - packages.lock.json (NuGet central package management
//     lockfile; the resolved-version source of truth)
//   - *.csproj / *.fsproj / *.vbproj (project files with
//     PackageReference items; the version source when no
//     lockfile is in use)
//
// A directory with BOTH a lockfile AND a project file emits both
// targets independently. Each Target is parsed and matched on its
// own; per-(ref, advisory ID) dedup is per-PackageRef, NOT global
// cross-target. The same package appearing in both the lockfile
// and the .csproj will produce one EcosystemResult entry per
// target and the matcher will hit each independently. This is
// intentional per-target visibility — a future PR can add
// cross-target collapsing if user feedback warrants it.
//
// Source labels: "packages.lock.json" for the lockfile,
// "csproj"/"fsproj"/"vbproj" (no leading dot) for project files
// so EcosystemResult entries distinguish them when several land
// in the same dir.
func pickNuGetTargets(dir string) []Target {
	var out []Target
	if statRegular(filepath.Join(dir, "packages.lock.json")) {
		out = append(out, Target{
			Ecosystem: intel.EcosystemNuGet,
			Path:      filepath.Join(dir, "packages.lock.json"),
			Source:    "packages.lock.json",
		})
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		switch ext {
		case ".csproj", ".fsproj", ".vbproj":
			out = append(out, Target{
				Ecosystem: intel.EcosystemNuGet,
				Path:      filepath.Join(dir, e.Name()),
				Source:    strings.TrimPrefix(ext, "."),
			})
		}
	}
	return out
}

func statRegular(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

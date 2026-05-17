package packagecheck

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/garagon/aguara/internal/intel"
)

// ParseComposer reads a composer.lock file and returns the
// declared Packagist dependencies, joining both the runtime
// `packages` array and the dev-only `packages-dev` array. Dev
// packages are included because malicious dev dependencies still
// run on the developer machine and frequently in CI.
//
// composer.lock entries often carry a `v` prefix on the version
// ("v3.5.0") while OSV Packagist records use the bare form
// ("3.5.0"). The parser preserves the lockfile's literal version
// in PackageRef.Version; the runner's version-alias step is what
// queries both forms so the matcher hits regardless of which
// convention OSV ships.
//
// No external commands. No network. installed.json under
// vendor/composer/ is intentionally NOT parsed in this first cut;
// composer.lock is authoritative for what the project resolved.
func ParseComposer(target Target) ([]PackageRef, error) {
	data, err := os.ReadFile(target.Path)
	if err != nil {
		return nil, fmt.Errorf("open composer.lock: %w", err)
	}

	var lock composerLockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse composer.lock: %w", err)
	}

	refs := make([]PackageRef, 0, len(lock.Packages)+len(lock.PackagesDev))
	appendPkgs := func(pkgs []composerPkg) {
		for _, p := range pkgs {
			if p.Name == "" || p.Version == "" {
				continue
			}
			refs = append(refs, PackageRef{
				Ecosystem: intel.EcosystemPackagist,
				// Packagist registry IDs are case-insensitive
				// (`vendor/Pkg` == `vendor/pkg`); lowering at
				// parse time keeps the runner's matcher index
				// hits consistent regardless of how the lockfile
				// spells the dependency.
				Name:    strings.ToLower(p.Name),
				Version: p.Version,
				Path:    target.Path,
				Source:  "composer.lock",
			})
		}
	}
	appendPkgs(lock.Packages)
	appendPkgs(lock.PackagesDev)
	return refs, nil
}

type composerLockfile struct {
	Packages    []composerPkg `json:"packages"`
	PackagesDev []composerPkg `json:"packages-dev"`
}

type composerPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

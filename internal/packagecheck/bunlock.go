package packagecheck

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/garagon/aguara/internal/intel"
)

// bunTrailingCommaRe matches a JSONC trailing comma -- a comma followed
// (after optional whitespace) by a closing `}` or `]`. bun.lock string
// values (package names, versions, integrity hashes) never contain `,}`
// or `,]`, so stripping these is safe and turns the JSONC document into
// strict JSON.
var bunTrailingCommaRe = regexp.MustCompile(`,(\s*[}\]])`)

// (exactNpmVersionRe is defined in pnpm.go: a strict three-component
// semver matcher shared across the npm lockfile parsers. It rejects
// dist-tags like `latest` and partial versions, so only a concrete
// resolved tuple is emitted.)

// ParseBunLock reads a Bun text lockfile (bun.lock, lockfileVersion 1+)
// and returns the declared npm packages. It is the Bun counterpart to
// ParsePNPMLock / ParseYarnLock: a freshly cloned Bun project carries
// bun.lock but no node_modules, so
//
//	git clone <bun repo>
//	aguara check .
//
// audits the locked set before `bun install` runs. Bun installs from the
// npm registry, so refs land in intel.EcosystemNPM with Source="bun.lock".
//
// Only the TEXT bun.lock is parsed here; the legacy binary bun.lockb is
// handled (with a clear error) at the discovery/runner layer, never
// silently. bun.lock is JSONC -- it carries trailing commas, which
// encoding/json rejects -- so the trailing commas are stripped (a safe
// transform, see bunTrailingCommaRe) and the document is decoded as
// strict JSON. Decoding the structured `packages` object (rather than
// scanning lines) makes the parser correct regardless of formatting:
// pretty-printed or compact, LF or CRLF, and a nested `packages` key
// under `workspaces` is never confused with the top-level resolved map.
//
// Each entry in the packages object has the resolved "<name>@<version>"
// as its array's first element, and Bun normalizes aliases there: an
// alias key like "my-lodash" still records its first element as the REAL
// package ("lodash@4.17.20"). Reading the first element therefore matches
// the real registry package, so an alias cannot hide a compromised
// dependency behind a local name. Conservative, mirroring the other npm
// parsers: an entry is emitted only when the first element maps to a
// usable npm name and an exact resolved version; anything with a protocol
// (git/file/workspace/...) or a range is skipped, malformed JSON yields
// no findings (never a panic), and results dedupe on (name, version) in
// deterministic order.
func ParseBunLock(target Target) ([]PackageRef, error) {
	data, err := os.ReadFile(target.Path)
	if err != nil {
		return nil, fmt.Errorf("open bun.lock: %w", err)
	}

	strict := bunTrailingCommaRe.ReplaceAll(data, []byte("$1"))
	var lock struct {
		Packages map[string][]json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(strict, &lock); err != nil {
		// A supported lockfile that does not decode must fail loudly,
		// like ParsePackageLock / ParsePNPMLock, so a corrupt bun.lock is
		// never mistaken for an audited project. A valid file with no
		// packages object simply yields zero refs below.
		return nil, fmt.Errorf("parse bun.lock: %w", err)
	}

	seen := map[string]bool{}
	var refs []PackageRef
	add := func(name, version string) {
		if name == "" || version == "" {
			return
		}
		composite := name + "@" + version
		if seen[composite] {
			return
		}
		seen[composite] = true
		refs = append(refs, PackageRef{
			Ecosystem: intel.EcosystemNPM,
			Name:      name,
			Version:   version,
			Path:      target.Path,
			Source:    "bun.lock",
		})
	}

	for _, arr := range lock.Packages {
		if len(arr) == 0 {
			continue
		}
		var first string
		if err := json.Unmarshal(arr[0], &first); err != nil {
			continue // first element is not a string locator
		}
		if name, version, ok := splitNameVersion(first); ok {
			add(name, version)
		}
	}

	sort.Slice(refs, func(i, j int) bool {
		return refs[i].Name+"@"+refs[i].Version < refs[j].Name+"@"+refs[j].Version
	})
	return refs, nil
}

// splitNameVersion splits a resolved "<name>@<version>" spec (scoped or
// unscoped) into a usable npm (name, version), returning ok=false when
// the name is not a valid npm identifier or the version is not an exact
// resolved version (a protocol or range is rejected).
func splitNameVersion(spec string) (name, version string, ok bool) {
	spec = strings.TrimSpace(spec)
	at := strings.LastIndexByte(spec, '@')
	if at <= 0 { // no '@', or a leading '@' with no version separator
		return "", "", false
	}
	rawName, version := spec[:at], spec[at+1:]
	canonical, valid := validNPMName(rawName)
	if !valid || !exactNpmVersionRe.MatchString(version) {
		return "", "", false
	}
	return canonical, version, true
}

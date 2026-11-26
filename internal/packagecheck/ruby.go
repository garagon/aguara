package packagecheck

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"

	"github.com/garagon/aguara/internal/intel"
)

// gemSpecLine matches a Gemfile.lock GEM/specs entry shaped
// `name (version)` or `name (version-platform)`. The capture groups
// are (name, version and optional platform); constraint lines like
// `rack (>= 1.0)` are filtered out by a follow-up check on the
// version string.
var gemSpecLine = regexp.MustCompile(`^(\S+)\s+\(([^)]+)\)$`)

// splitGemPlatform separates a platform gem's version from its
// platform. Bundler writes a spec as `name (version-platform)` when the
// platform is not `ruby`, and its own lockfile parser reads the version
// as the text before the first "-" (Bundler::LockfileParser
// NAME_VERSION); Gem::Version never contains "-" because it rewrites
// one as ".pre.". The platform build of a release is the same RubyGems
// version, which is what advisories list, so `nokogiri
// (1.16.2-arm64-darwin)` is version 1.16.2.
func splitGemPlatform(spec string) (version, platform string) {
	version, platform, _ = strings.Cut(spec, "-")
	return version, platform
}

// ParseRuby reads a Gemfile.lock and returns the installed gems
// declared in the GEM section's specs sub-block. Only top-level
// gem entries (4-space indent) are emitted; their nested
// dependency-constraint lines (6-space indent) are ignored
// because they describe what the gem requires, not what bundler
// resolved.
//
// Sections other than GEM (GIT, PLATFORMS, DEPENDENCIES,
// BUNDLED WITH) are skipped: GIT-source gems are not in the
// RubyGems registry the matcher consults; PLATFORMS /
// DEPENDENCIES / BUNDLED WITH carry no version-resolution data.
//
// No external commands. No network.
func ParseRuby(target Target) ([]PackageRef, error) {
	f, err := openManifest(target.Path, "Gemfile.lock")
	if err != nil {
		return nil, fmt.Errorf("open Gemfile.lock: %w", err)
	}
	defer func() { _ = f.Close() }()

	var refs []PackageRef
	seen := map[string]bool{}
	inGEM := false
	inSpecs := false

	scanner := bufio.NewScanner(boundedManifestReader(f, maxManifestBytes, "Gemfile.lock"))
	for scanner.Scan() {
		raw := scanner.Text()
		if raw == "" {
			continue
		}
		// Section headers sit at column 0 (no indent). Switching
		// sections always resets the in-specs flag.
		if !strings.HasPrefix(raw, " ") {
			inGEM = raw == "GEM"
			inSpecs = false
			continue
		}
		if !inGEM {
			continue
		}
		if strings.TrimSpace(raw) == "specs:" {
			inSpecs = true
			continue
		}
		if !inSpecs {
			// Inside GEM but not in specs: `remote:`,
			// `revision:`, etc.
			continue
		}
		// Within specs: 4-space indent = top-level gem,
		// 6-space (or more) indent = dependency constraint
		// (skip). A line that drops below 4-space indent
		// signals the end of specs for this block.
		if strings.HasPrefix(raw, "      ") {
			continue
		}
		if !strings.HasPrefix(raw, "    ") {
			inSpecs = false
			continue
		}
		line := strings.TrimSpace(raw)
		match := gemSpecLine.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		name, version := match[1], match[2]
		if name == "" || version == "" {
			continue
		}
		// Constraint operators inside the version paren only
		// appear on dependency-line entries (which the indent
		// check above should have skipped); double-checking
		// here keeps a malformed lockfile from producing a
		// nonsense PackageRef.
		if strings.ContainsAny(version, "<>=~") {
			continue
		}
		if version, _ = splitGemPlatform(version); version == "" {
			continue
		}
		// RubyGems registry IDs are usually lowercase already;
		// case-fold here for the same reason Composer does (matcher
		// index consistency). Platform builds of one release fold
		// into one ref.
		name = strings.ToLower(name)
		if seen[name+"\x00"+version] {
			continue
		}
		if err := checkEntryLimit(len(refs), "Gemfile.lock"); err != nil {
			return nil, err
		}
		seen[name+"\x00"+version] = true
		refs = append(refs, PackageRef{
			Ecosystem: intel.EcosystemRubyGems,
			Name:      name,
			Version:   version,
			Path:      target.Path,
			Source:    "Gemfile.lock",
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read Gemfile.lock: %w", err)
	}
	return refs, nil
}

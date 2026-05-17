package packagecheck

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/garagon/aguara/internal/intel"
)

// gemSpecLine matches a Gemfile.lock GEM/specs entry shaped
// `name (version)`. The capture groups are (name, version);
// constraint lines like `rack (>= 1.0)` are filtered out by a
// follow-up check on the version string. Platform-specific
// versions (e.g. `1.16.2-arm64-darwin`) pass through unchanged
// because they are valid exact-version identifiers in OSV.
var gemSpecLine = regexp.MustCompile(`^(\S+)\s+\(([^)]+)\)$`)

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
	f, err := os.Open(target.Path)
	if err != nil {
		return nil, fmt.Errorf("open Gemfile.lock: %w", err)
	}
	defer func() { _ = f.Close() }()

	var refs []PackageRef
	inGEM := false
	inSpecs := false

	scanner := bufio.NewScanner(f)
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
		refs = append(refs, PackageRef{
			Ecosystem: intel.EcosystemRubyGems,
			// RubyGems registry IDs are usually lowercase
			// already; case-fold here for the same reason
			// Composer does (matcher index consistency).
			Name:    strings.ToLower(name),
			Version: version,
			Path:    target.Path,
			Source:  "Gemfile.lock",
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read Gemfile.lock: %w", err)
	}
	return refs, nil
}

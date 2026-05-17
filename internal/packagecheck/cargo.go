package packagecheck

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/garagon/aguara/internal/intel"
)

// ParseCargo reads a Cargo.lock file and returns the declared
// crates.io dependencies. The parser is intentionally a
// block-level reader, not a full TOML implementation: Cargo.lock
// is a stable, machine-generated format whose only fields we need
// (name, version, source) are flat key/value pairs inside repeated
// `[[package]]` arrays.
//
// Only entries sourced from the crates.io registry are returned;
// see isCratesIORegistrySource. Cargo lockfile entries from
// private registries, git sources, path dependencies, or
// workspace members are skipped: the OSV matcher resolves
// identifiers under the crates.io ecosystem, so non-crates.io
// crates would either never match (best case) or false-positive
// on a name collision with a public crate (worst case). The
// allowlist closes the false-positive door.
//
// No external commands. No network.
func ParseCargo(target Target) ([]PackageRef, error) {
	f, err := os.Open(target.Path)
	if err != nil {
		return nil, fmt.Errorf("open Cargo.lock: %w", err)
	}
	defer func() { _ = f.Close() }()

	var (
		refs    []PackageRef
		inBlock bool
		cur     cargoPkg
	)
	flush := func() {
		// Only emit when the block declared a crates.io registry
		// source AND we captured name + version. Private registries,
		// git deps, path deps, and workspace members (no source)
		// fall through silently: the OSV matcher resolves
		// identifiers under the crates.io ecosystem only, so
		// emitting a private-registry crate with a name that
		// collides with a public advisory would false-positive.
		if isCratesIORegistrySource(cur.source) && cur.name != "" && cur.version != "" {
			refs = append(refs, PackageRef{
				Ecosystem: intel.EcosystemCargo,
				Name:      cur.name,
				Version:   cur.version,
				Path:      target.Path,
				Source:    "Cargo.lock",
			})
		}
		cur = cargoPkg{}
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case line == "[[package]]":
			if inBlock {
				flush()
			}
			inBlock = true
			continue
		case strings.HasPrefix(line, "[["), strings.HasPrefix(line, "["):
			// Any other table / array-of-tables header
			// ([metadata], [[patch]]) terminates the current
			// package block.
			if inBlock {
				flush()
			}
			inBlock = false
			continue
		}
		if !inBlock {
			continue
		}
		key, value, ok := parseCargoKV(line)
		if !ok {
			continue
		}
		switch key {
		case "name":
			cur.name = value
		case "version":
			cur.version = value
		case "source":
			cur.source = value
		}
	}
	if inBlock {
		flush()
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read Cargo.lock: %w", err)
	}
	return refs, nil
}

type cargoPkg struct{ name, version, source string }

// isCratesIORegistrySource is the allowlist of `source = "..."`
// values that mean "this crate came from the public crates.io
// registry". Two forms exist in the wild:
//
//   - registry+https://github.com/rust-lang/crates.io-index
//     The historical git-based index. Cargo writes this for
//     every crate when the user runs against the default registry
//     on Rust toolchains prior to 1.70 (and on 1.70+ when the
//     legacy index protocol is selected).
//   - sparse+https://index.crates.io/
//     The sparse HTTP index Cargo adopted as the default in
//     1.70 (RFC 2789). Newer lockfiles regenerated on Rust 1.70+
//     carry this form for crates.io entries.
//
// A `registry+...` source pointing at any OTHER URL is a
// private registry (Cloudsmith, JFrog Artifactory, AWS
// CodeArtifact, an internal mirror, etc.). The packages those
// registries host are unrelated to crates.io OSV advisories;
// matching a private `serde 1.0.197` against a crates.io
// `serde 1.0.197` advisory would be a false positive.
//
// New entries here require evidence that the URL canonically
// serves the crates.io catalog under a different protocol.
func isCratesIORegistrySource(source string) bool {
	switch source {
	case "registry+https://github.com/rust-lang/crates.io-index",
		"sparse+https://index.crates.io/":
		return true
	default:
		return false
	}
}

// parseCargoKV splits a single `key = "value"` line into its parts
// and strips the surrounding double quotes. Returns ok=false for
// lines that do not match the simple flat-string shape (e.g.
// `dependencies = [...]`), which the caller silently skips.
func parseCargoKV(line string) (string, string, bool) {
	eq := strings.IndexByte(line, '=')
	if eq < 0 {
		return "", "", false
	}
	key := strings.TrimSpace(line[:eq])
	value := strings.TrimSpace(line[eq+1:])
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		// Array values (dependencies = [...]) and other shapes
		// land here. Cargo.lock fields we consume are always
		// quoted strings, so ignoring the rest is safe.
		return "", "", false
	}
	value = value[1 : len(value)-1]
	return key, value, true
}

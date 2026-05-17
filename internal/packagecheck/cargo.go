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
// Only registry-sourced packages are returned. Cargo lockfile
// entries with a `source = "git+..."` or no source at all
// (workspace members, path dependencies) are skipped: the OSV
// matcher resolves identifiers under the crates.io ecosystem, so
// non-registry crates would never match anyway and including them
// would inflate packages_read with names the runtime cannot act
// on.
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
		// source AND we captured name + version. Workspace members
		// (no source), git deps, and path deps fall through
		// silently because the matcher cannot consume them.
		if strings.HasPrefix(cur.source, "registry+") && cur.name != "" && cur.version != "" {
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

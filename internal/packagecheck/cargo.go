package packagecheck

import (
	"fmt"

	"github.com/garagon/aguara/internal/intel"
	"github.com/pelletier/go-toml/v2/unstable"
)

// ParseCargo decodes Cargo.lock as TOML and returns only packages from the
// public crates.io registries. Unknown tables and fields are not package data.
// It does not execute Cargo, resolve dependencies, or access the network.
func ParseCargo(target Target) ([]PackageRef, error) {
	data, err := readManifest(target.Path, "Cargo.lock")
	if err != nil {
		return nil, fmt.Errorf("read Cargo.lock: %w", err)
	}

	return parseCargoBytes(data, target.Path)
}

// Parse syntax expression-by-expression instead of materializing arbitrary
// metadata. The general TOML decoder's duplicate-key tracker searches all prior
// siblings; using it on untrusted metadata can turn a bounded file into quadratic
// work. Only Cargo's [[package]] identity fields need semantic interpretation.
func parseCargoBytes(data []byte, path string) ([]PackageRef, error) {
	var parser unstable.Parser
	parser.Reset(data)
	var refs []PackageRef
	var fields map[string]string
	flush := func() {
		if isCratesIORegistrySource(fields["source"]) && fields["name"] != "" && fields["version"] != "" {
			refs = append(refs, PackageRef{Ecosystem: intel.EcosystemCargo, Name: fields["name"], Version: fields["version"], Path: path, Source: "Cargo.lock"})
		}
	}
	atRoot := true
	for parser.NextExpression() {
		expr := parser.Expression()
		keys := expr.Key()
		var first, second string
		count := 0
		for keys.Next() {
			count++
			switch count {
			case 1:
				first = string(keys.Node().Data)
			case 2:
				second = string(keys.Node().Data)
			}
		}
		switch expr.Kind {
		case unstable.Table, unstable.ArrayTable:
			flush()
			fields = nil
			atRoot = false
			if first == "package" {
				if count == 1 {
					if expr.Kind != unstable.ArrayTable {
						return nil, fmt.Errorf("parse Cargo.lock: package must be an array of tables")
					}
					fields = make(map[string]string, 3)
				} else if cargoIdentityField(second) {
					return nil, fmt.Errorf("parse Cargo.lock: package identity cannot be a table")
				}
			}
		case unstable.KeyValue:
			if atRoot && first == "package" {
				return nil, fmt.Errorf("parse Cargo.lock: expected [[package]] tables")
			}
			if fields == nil || !cargoIdentityField(first) {
				continue
			}
			if count != 1 || expr.Value().Kind != unstable.String {
				return nil, fmt.Errorf("parse Cargo.lock: package %s must be a string", first)
			}
			if _, exists := fields[first]; exists {
				return nil, fmt.Errorf("parse Cargo.lock: duplicate package %s", first)
			}
			fields[first] = string(expr.Value().Data)
		}
	}
	if parser.Error() != nil {
		// Parser diagnostics may quote credential-bearing input.
		return nil, fmt.Errorf("parse Cargo.lock: invalid TOML syntax")
	}
	flush()
	return refs, nil
}

func cargoIdentityField(key string) bool {
	return key == "name" || key == "version" || key == "source"
}

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

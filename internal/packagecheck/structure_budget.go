package packagecheck

import (
	"bytes"
	"encoding/xml"
	"fmt"
)

// Structure budgets for dependency files decoded as a whole document
// (JSON, YAML, XML). The decoders materialise every value before any
// semantic check runs, and a 50 MiB document made of one-byte values
// costs gigabytes: a package-lock.json of empty entries peaked at 2.2 GiB,
// a pnpm-lock.yaml flow sequence at 4.2 GiB. A cheap lexical pass rejects
// such documents before decoding.
//
// The counts over-approximate the decoded values. Real lockfiles are far
// below the limit: package-lock.json averages about 45 bytes per counted
// node, so the limit is about 90 MB of lockfile, above the 50 MiB file
// limit; pnpm-lock.yaml, whose count includes every ':' and '-'
// (integrity hashes, URLs), about 12 bytes per node, about 24 MB of
// lockfile. A document of the worst shape just under the limit peaks
// below 1 GiB (measured, process included).
// maxLockfileEntries bounds the package references one dependency file
// may produce, the same bound the Python lockfiles have
// (maxPythonLockEntries). Real lockfiles hold a few thousand packages. A
// variable so tests can lower it.
var maxLockfileEntries = 100_000

const (
	// maxStructuredNodes bounds the lexical node count of a JSON or
	// YAML document and the token count of an XML document.
	maxStructuredNodes = 2_000_000
	// maxXMLDepth bounds XML element nesting. encoding/xml has no
	// nesting limit of its own; real POMs and project files nest fewer
	// than ten levels. JSON (encoding/json) and YAML (yaml.v3) reject
	// nesting deeper than 10,000 levels themselves.
	maxXMLDepth = 256
)

// errEntryLimit reports a dependency file with too many package entries.
func errEntryLimit(label string) error {
	return fmt.Errorf("parse %s: more than %d package entries", label, maxLockfileEntries)
}

// checkEntryLimit fails once refs would exceed maxLockfileEntries. Line
// parsers call it before every append, so the refs never grow past it.
func checkEntryLimit(n int, label string) error {
	if n >= maxLockfileEntries {
		return errEntryLimit(label)
	}
	return nil
}

// CheckJSONNodeBudget applies the JSON structure budget to a document read
// outside this package (installed package manifests).
func CheckJSONNodeBudget(data []byte, label string) error {
	return checkJSONNodeBudget(data, label)
}

// checkJSONNodeBudget counts the bytes that can start a JSON value outside
// strings: '{', '[' and ','. Each value except the first of a container
// follows a ',', and each container starts with a bracket.
func checkJSONNodeBudget(data []byte, label string) error {
	count := 1
	for i := 0; i < len(data); i++ {
		switch data[i] {
		case '"':
			for i++; i < len(data) && data[i] != '"'; i++ {
				if data[i] == '\\' {
					i++
				}
			}
		case '{', '[', ',':
			count++
			if count > maxStructuredNodes {
				return fmt.Errorf("parse %s: document exceeds the %d-node limit", label, maxStructuredNodes)
			}
		}
	}
	return nil
}

// checkYAMLNodeBudget counts the bytes that can start or separate a YAML
// node outside quoted scalars and comments: line breaks, ':', '-', '?',
// flow brackets and ','. A ',' inside a flow mapping counts twice, because
// an entry without ':' there is a key with an implicit null value.
func checkYAMLNodeBudget(data []byte, label string) error {
	count := 1
	var flow []byte // open flow collections, innermost last
	for i := 0; i < len(data); i++ {
		add := 0
		switch c := data[i]; c {
		case '#':
			if i == 0 || data[i-1] == ' ' || data[i-1] == '\t' || data[i-1] == '\n' || data[i-1] == '\r' {
				for i < len(data) && data[i] != '\n' {
					i++
				}
				add = 1 // the line break that ends the comment
			}
		case '\'':
			for i++; i < len(data) && data[i] != '\''; i++ {
			}
		case '"':
			for i++; i < len(data) && data[i] != '"'; i++ {
				if data[i] == '\\' {
					i++
				}
			}
		case '[', '{':
			flow = append(flow, c) // bounded: every bracket also counts
			add = 1
		case ']', '}':
			if len(flow) > 0 {
				flow = flow[:len(flow)-1]
			}
		case ',':
			add = 1
			if len(flow) > 0 && flow[len(flow)-1] == '{' {
				add = 2
			}
		case '\n', ':', '-', '?':
			add = 1
		}
		count += add
		if count > maxStructuredNodes {
			return fmt.Errorf("parse %s: document exceeds the %d-node limit", label, maxStructuredNodes)
		}
	}
	return nil
}

// checkXMLBudget walks the raw XML tokens, which keeps no element stack,
// and bounds their number and the element nesting before the document is
// unmarshalled. A syntax error ends the walk without an error: the
// decoder that follows reports it in its usual words.
func checkXMLBudget(data []byte, label string) error {
	d := xml.NewDecoder(bytes.NewReader(data))
	depth, tokens := 0, 0
	for {
		tok, err := d.RawToken()
		if err != nil {
			return nil // end of input, or a syntax error Unmarshal reports
		}
		tokens++
		if tokens > maxStructuredNodes {
			return fmt.Errorf("parse %s: document exceeds the %d-token limit", label, maxStructuredNodes)
		}
		switch tok.(type) {
		case xml.StartElement:
			depth++
			if depth > maxXMLDepth {
				return fmt.Errorf("parse %s: elements nest more than %d levels deep", label, maxXMLDepth)
			}
		case xml.EndElement:
			if depth > 0 {
				depth--
			}
		}
	}
}

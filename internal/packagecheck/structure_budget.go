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
// such documents before decoding: it bounds the number of values in the
// document and the number of members of any one object, array, mapping
// or sequence, so the entry limit holds before a wide container is
// materialised.
//
// The counts over-approximate the decoded values. Real lockfiles are far
// below the limits: package-lock.json averages about 45 bytes per counted
// node, so the node limit is about 90 MB of lockfile, above the 50 MiB
// file limit; pnpm-lock.yaml, whose count includes every ':' and '-'
// (integrity hashes, URLs), about 12 bytes per node, about 24 MB of
// lockfile.
const (
	// maxStructuredNodes bounds the lexical node count of a JSON or
	// YAML document and the token count of an XML document.
	maxStructuredNodes = 2_000_000
	// maxContainerMembers bounds the members of one JSON object or
	// array, or the entries of one YAML mapping or sequence. It equals
	// maxLockfileEntries but counts something else: members are counted
	// before decoding, entries are the (name, version) references left
	// after deduplication. A package-lock.json "packages" object has one
	// member per install path, and a package installed at several paths
	// is one entry, so a lockfile with more than 100,000 install paths is
	// rejected here even when it holds fewer unique packages. Real
	// lockfiles hold a few thousand install paths.
	maxContainerMembers = 100_000
	// maxXMLDepth bounds XML element nesting. encoding/xml has no
	// nesting limit of its own; real POMs and project files nest fewer
	// than ten levels. JSON (encoding/json) and YAML (yaml.v3) reject
	// nesting deeper than 10,000 levels themselves.
	maxXMLDepth = 256
)

// maxLockfileEntries bounds the package references one dependency file
// may produce, the same bound the Python lockfiles have
// (maxPythonLockEntries). Real lockfiles hold a few thousand packages. A
// variable so tests can lower it.
var maxLockfileEntries = 100_000

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

func errNodeLimit(label string) error {
	return fmt.Errorf("parse %s: document exceeds the %d-node limit", label, maxStructuredNodes)
}

func errContainerLimit(label string) error {
	return fmt.Errorf("parse %s: a collection has more than %d members", label, maxContainerMembers)
}

// checkJSONNodeBudget counts the bytes that can start a JSON value outside
// strings: '{', '[' and ','. Each value except the first of a container
// follows a ',', and each container starts with a bracket. The ','s of each
// open container are counted too, for the member limit.
func checkJSONNodeBudget(data []byte, label string) error {
	count := 1
	var commas []int // per open container, innermost last
	for i := 0; i < len(data); i++ {
		switch data[i] {
		case '"':
			for i++; i < len(data) && data[i] != '"'; i++ {
				if data[i] == '\\' {
					i++
				}
			}
			continue
		case '{', '[':
			commas = append(commas, 0) // bounded: every bracket also counts
		case ']', '}':
			if len(commas) > 0 {
				commas = commas[:len(commas)-1]
			}
			continue
		case ',':
			if n := len(commas); n > 0 {
				if commas[n-1]++; commas[n-1] >= maxContainerMembers {
					return errContainerLimit(label)
				}
			}
		default:
			continue
		}
		if count++; count > maxStructuredNodes {
			return errNodeLimit(label)
		}
	}
	return nil
}

// checkYAMLNodeBudget counts the bytes that can start or separate a YAML
// node outside quoted scalars and comments: line breaks, ':', '-', '?',
// flow brackets and ','. A ',' inside a flow mapping counts twice, because
// an entry without ':' there is a key with an implicit null value.
//
// For the member limit it counts the ','s of each open flow collection
// and, outside flow collections, the lines that start at each indentation
// of the open block collections: every entry of a block mapping or
// sequence starts a line at the collection's indentation. Lines of a block
// scalar count as entries of a deeper collection, which only
// over-approximates.
func checkYAMLNodeBudget(data []byte, label string) error {
	type flowOpen struct {
		kind   byte
		commas int
	}
	type blockLevel struct{ indent, entries int }
	count := 1
	var flow []flowOpen
	var block []blockLevel
	lineStart := true
	for i := 0; i < len(data); i++ {
		if lineStart {
			lineStart = false
			if len(flow) == 0 {
				j := i
				for j < len(data) && data[j] == ' ' {
					j++
				}
				if j < len(data) && data[j] != '\n' && data[j] != '\r' && data[j] != '#' {
					indent := j - i
					for len(block) > 0 && block[len(block)-1].indent > indent {
						block = block[:len(block)-1]
					}
					if n := len(block); n > 0 && block[n-1].indent == indent {
						if block[n-1].entries++; block[n-1].entries > maxContainerMembers {
							return errContainerLimit(label)
						}
					} else {
						block = append(block, blockLevel{indent: indent, entries: 1})
					}
				}
			}
		}
		add := 0
		switch c := data[i]; c {
		case '#':
			if i == 0 || data[i-1] == ' ' || data[i-1] == '\t' || data[i-1] == '\n' || data[i-1] == '\r' {
				// Skip to the line break, which the next iteration counts.
				for i+1 < len(data) && data[i+1] != '\n' {
					i++
				}
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
			flow = append(flow, flowOpen{kind: c}) // bounded: every bracket also counts
			add = 1
		case ']', '}':
			if len(flow) > 0 {
				flow = flow[:len(flow)-1]
			}
		case ',':
			add = 1
			if n := len(flow); n > 0 {
				if flow[n-1].kind == '{' {
					add = 2
				}
				if flow[n-1].commas++; flow[n-1].commas >= maxContainerMembers {
					return errContainerLimit(label)
				}
			}
		case '\n':
			add = 1
			lineStart = true
		case ':', '-', '?':
			add = 1
		}
		count += add
		if count > maxStructuredNodes {
			return errNodeLimit(label)
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

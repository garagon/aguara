// Package schematest validates report output against JSON Schema files in
// tests. It is imported only from _test.go files, so the validator is not
// linked into the aguara binary.
package schematest

import (
	"encoding/json"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/go-openapi/spec"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/validate"
)

// formats is the validator's format registry: the go-openapi defaults
// plus "uri-reference" (RFC 3986), which the SARIF schema uses for
// artifact URIs and the defaults do not check.
var formats = func() strfmt.Registry {
	r := strfmt.NewFormats()
	var u uriReference
	r.Add("uri-reference", &u, IsURIReference)
	return r
}()

type uriReference string

func (u uriReference) String() string               { return string(u) }
func (u uriReference) MarshalText() ([]byte, error) { return []byte(u), nil }
func (u *uriReference) UnmarshalText(b []byte) error {
	*u = uriReference(b)
	return nil
}

// IsURIReference reports whether s is an RFC 3986 URI reference: only
// unreserved, reserved and percent-encoded characters, every "%" followed
// by two hex digits, and parseable as a URL.
func IsURIReference(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("-._~:/?#[]@!$&'()*+,;=", c) >= 0:
		case c == '%':
			if i+2 >= len(s) || !isHex(s[i+1]) || !isHex(s[i+2]) {
				return false
			}
			i += 2
		default:
			return false
		}
	}
	_, err := url.Parse(s)
	return err == nil
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

type cacheKey struct {
	path     string
	expanded bool
}

var (
	cacheMu sync.Mutex
	cache   = map[cacheKey]*spec.Schema{}
)

// Load reads a JSON Schema file for Validate. Local "#/definitions/..."
// references are resolved by the validator as it meets them, which is far
// cheaper than expanding a large schema such as SARIF's; the schema's own
// id is not fetched. Schemas are cached per path for the life of the test
// binary.
func Load(t testing.TB, path string) *spec.Schema {
	t.Helper()
	return cached(t, path, false)
}

// LoadExpanded reads a JSON Schema file with every local reference
// replaced by its definition, for Undocumented and for validating against
// one definition on its own.
func LoadExpanded(t testing.TB, path string) *spec.Schema {
	t.Helper()
	return cached(t, path, true)
}

func cached(t testing.TB, path string, expanded bool) *spec.Schema {
	t.Helper()
	cacheMu.Lock()
	defer cacheMu.Unlock()
	key := cacheKey{path, expanded}
	if s, ok := cache[key]; ok {
		return s
	}
	s := load(t, path, expanded)
	cache[key] = s
	return s
}

func load(t testing.TB, path string, expand bool) *spec.Schema {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read schema %s: %v", path, err)
	}
	var schema spec.Schema
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("parse schema %s: %v", path, err)
	}
	// An absolute id would make the validator resolve references against
	// the network location; the files are self-contained.
	schema.ID = ""
	if expand {
		if err := spec.ExpandSchema(&schema, &schema, nil); err != nil {
			t.Fatalf("expand schema %s: %v", path, err)
		}
	}
	return &schema
}

// Validate fails the test when doc (JSON bytes) does not satisfy schema.
func Validate(t testing.TB, schema *spec.Schema, doc []byte) {
	t.Helper()
	var v any
	if err := json.Unmarshal(doc, &v); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	if err := validate.AgainstSchema(schema, v, formats); err != nil {
		t.Fatalf("output does not match the schema:\n%v", err)
	}
}

// Undocumented returns the JSON paths of object members in doc that the
// schema (loaded with LoadExpanded) does not describe in any `properties` (including through allOf),
// so a published schema cannot silently fall behind the output it
// describes. Members of objects without declared properties are not
// checked.
func Undocumented(t testing.TB, schema *spec.Schema, doc []byte) []string {
	t.Helper()
	var v any
	if err := json.Unmarshal(doc, &v); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	var missing []string
	walk(schema, v, "$", &missing)
	sort.Strings(missing)
	return missing
}

func walk(s *spec.Schema, v any, path string, missing *[]string) {
	if s == nil {
		return
	}
	switch val := v.(type) {
	case map[string]any:
		props := map[string]*spec.Schema{}
		collectProperties(s, props)
		if len(props) == 0 {
			return
		}
		for key, child := range val {
			ps, ok := props[key]
			if !ok {
				*missing = append(*missing, path+"."+key)
				continue
			}
			walk(ps, child, path+"."+key, missing)
		}
	case []any:
		var items *spec.Schema
		if s.Items != nil {
			items = s.Items.Schema
		}
		for _, child := range val {
			walk(items, child, path+"[]", missing)
		}
	}
}

func collectProperties(s *spec.Schema, into map[string]*spec.Schema) {
	for name := range s.Properties {
		prop := s.Properties[name]
		into[name] = &prop
	}
	for i := range s.AllOf {
		collectProperties(&s.AllOf[i], into)
	}
}

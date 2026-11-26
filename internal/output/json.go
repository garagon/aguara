package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
)

// ReportSchemaVersion is the version of the JSON report contract of the
// scan, check and audit commands, and of the schema files published under
// schema/. Additive changes (new fields, new enum values documented as
// open) bump the minor version; a change that removes or renames a field
// or changes its type bumps the major version. Consumers should accept any
// 1.x report and ignore fields they do not know.
const ReportSchemaVersion = "1.0"

// ReportHeader identifies a JSON report: the contract version, the build
// that produced it and the rule catalog it used. It is written as the
// first fields of the top-level object.
type ReportHeader struct {
	SchemaVersion string             `json:"schema_version"`
	Tool          types.ToolInfo     `json:"tool"`
	Catalog       *types.CatalogInfo `json:"catalog,omitempty"`
}

// JSONFormatter outputs a scan result as JSON. With a Header, the report
// starts with schema_version, tool and catalog.
type JSONFormatter struct {
	Header *ReportHeader
}

func (f *JSONFormatter) Format(w io.Writer, result *scanner.ScanResult) error {
	return EncodeJSONReport(w, f.Header, result)
}

// EncodeJSONReport writes v, which must encode as a JSON object, indented
// with two spaces and followed by a newline. A non-nil header's fields are
// placed first. Without a header the output is exactly v's encoding.
func EncodeJSONReport(w io.Writer, header *ReportHeader, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if header != nil {
		head, err := json.Marshal(header)
		if err != nil {
			return err
		}
		if len(body) < 2 || body[0] != '{' {
			return fmt.Errorf("json report: %T does not encode as an object", v)
		}
		merged := make([]byte, 0, len(head)+len(body))
		merged = append(merged, head[:len(head)-1]...)
		if len(body) > 2 {
			merged = append(merged, ',')
		}
		merged = append(merged, body[1:]...)
		body = merged
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, body, "", "  "); err != nil {
		return err
	}
	buf.WriteByte('\n')
	_, err = w.Write(buf.Bytes())
	return err
}

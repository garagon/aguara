// Package jsonfields decodes modeled JSON properties without case folding.
package jsonfields

import (
	"encoding/json"
	"sort"
)

type Field struct {
	Name string
	To   any
}

// Map resolves duplicate dynamic keys before type checking their final values.
type Map[V any] map[string]V

func (m *Map[V]) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw == nil {
		*m = nil
		return nil
	}
	keys := make([]string, 0, len(raw))
	for key := range raw {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	next := make(Map[V], len(raw))
	for _, key := range keys {
		var value V
		if err := json.Unmarshal(raw[key], &value); err != nil {
			return err
		}
		next[key] = value
	}
	*m = next
	return nil
}

// Decode resolves duplicate properties before decoding their final values.
// Callers supply fresh destinations; missing properties leave them untouched.
// Field order determines which error is returned when multiple values are bad.
func Decode(data []byte, fields ...Field) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return err
	}
	for _, field := range fields {
		if raw, ok := object[field.Name]; ok {
			if err := json.Unmarshal(raw, field.To); err != nil {
				return err
			}
		}
	}
	return nil
}

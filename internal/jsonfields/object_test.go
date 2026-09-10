package jsonfields

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodeExactFinalFields(t *testing.T) {
	for _, tc := range []struct {
		input, want string
		bad         bool
	}{
		{`{"key":"yes","Key":"no"}`, "yes", false},
		{`{"Key":42}`, "", false},
		{`{"key":42,"key":"final"}`, "final", false},
		{`{"key":"old","key":null}`, "", false},
		{`{"\u006bey":"escaped","\u212aey":"unrelated"}`, "escaped", false},
		{`{"key":42}`, "", true},
		{`[]`, "", true},
		{`null`, "", false},
	} {
		var value string
		err := Decode([]byte(tc.input), Field{Name: "key", To: &value})
		require.Equal(t, tc.bad, err != nil, tc.input)
		require.Equal(t, tc.want, value, tc.input)
	}
}

func TestMapDecodesFinalValues(t *testing.T) {
	var got Map[string]
	require.NoError(t, json.Unmarshal([]byte(`{"a":42,"a":"final","b":"old","b":null}`), &got))
	require.Equal(t, Map[string]{"a": "final", "b": ""}, got)
	require.NoError(t, json.Unmarshal([]byte(`{}`), &got))
	require.Empty(t, got)
	require.NoError(t, json.Unmarshal([]byte(`null`), &got))
	require.Nil(t, got)
	require.Error(t, json.Unmarshal([]byte(`{"a":"old","a":42}`), &got))
	require.Nil(t, got, "failed decoding must not assign partial data")
}

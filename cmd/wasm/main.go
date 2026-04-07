//go:build js && wasm

package main

import (
	"context"
	"encoding/json"
	"syscall/js"

	"github.com/garagon/aguara"
)

func main() {
	js.Global().Set("aguaraScanContent", js.FuncOf(scanContent))
	js.Global().Set("aguaraScanContentAs", js.FuncOf(scanContentAs))
	js.Global().Set("aguaraListRules", js.FuncOf(listRules))
	js.Global().Set("aguaraExplainRule", js.FuncOf(explainRule))
	js.Global().Set("aguaraVersion", js.FuncOf(version))
	select {}
}

// aguaraScanContent(content, filename, [options]) -> Promise<JSON>
func scanContent(this js.Value, args []js.Value) any {
	if len(args) < 2 {
		return jsError("aguaraScanContent requires 2 arguments: content, filename")
	}
	content := args[0].String()
	filename := args[1].String()
	opts := parseOptions(args, 2)

	return newPromise(func() (any, error) {
		return aguara.ScanContent(context.Background(), content, filename, opts...)
	})
}

// aguaraScanContentAs(content, filename, toolName, [options]) -> Promise<JSON>
func scanContentAs(this js.Value, args []js.Value) any {
	if len(args) < 3 {
		return jsError("aguaraScanContentAs requires 3 arguments: content, filename, toolName")
	}
	content := args[0].String()
	filename := args[1].String()
	toolName := args[2].String()
	opts := parseOptions(args, 3)

	return newPromise(func() (any, error) {
		return aguara.ScanContentAs(context.Background(), content, filename, toolName, opts...)
	})
}

// aguaraListRules() -> JSON string
func listRules(this js.Value, args []js.Value) any {
	rules := aguara.ListRules()
	b, err := json.Marshal(rules)
	if err != nil {
		return jsError(err.Error())
	}
	return string(b)
}

// aguaraExplainRule(ruleID) -> JSON string
func explainRule(this js.Value, args []js.Value) any {
	if len(args) < 1 {
		return jsError("aguaraExplainRule requires 1 argument: ruleID")
	}
	id := args[0].String()
	detail, err := aguara.ExplainRule(id)
	if err != nil {
		return jsError(err.Error())
	}
	b, err := json.Marshal(detail)
	if err != nil {
		return jsError(err.Error())
	}
	return string(b)
}

// aguaraVersion() -> string
func version(this js.Value, args []js.Value) any {
	return "wasm"
}

// parseOptions extracts scan options from a JS object argument at the given index.
// Supported fields: minSeverity (string), profile (string).
func parseOptions(args []js.Value, idx int) []aguara.Option {
	if len(args) <= idx || args[idx].IsUndefined() || args[idx].IsNull() {
		return nil
	}
	obj := args[idx]
	var opts []aguara.Option

	if sev := obj.Get("minSeverity"); !sev.IsUndefined() && !sev.IsNull() {
		switch sev.String() {
		case "low":
			opts = append(opts, aguara.WithMinSeverity(aguara.SeverityLow))
		case "medium":
			opts = append(opts, aguara.WithMinSeverity(aguara.SeverityMedium))
		case "high":
			opts = append(opts, aguara.WithMinSeverity(aguara.SeverityHigh))
		case "critical":
			opts = append(opts, aguara.WithMinSeverity(aguara.SeverityCritical))
		}
	}

	if profile := obj.Get("profile"); !profile.IsUndefined() && !profile.IsNull() {
		switch profile.String() {
		case "content-aware":
			opts = append(opts, aguara.WithScanProfile(aguara.ProfileContentAware))
		case "minimal":
			opts = append(opts, aguara.WithScanProfile(aguara.ProfileMinimal))
		}
	}

	return opts
}

// newPromise creates a JS Promise that runs fn in a goroutine and resolves with JSON.
func newPromise(fn func() (any, error)) js.Value {
	handler := js.FuncOf(func(_ js.Value, promiseArgs []js.Value) any {
		resolve := promiseArgs[0]
		reject := promiseArgs[1]

		go func() {
			result, err := fn()
			if err != nil {
				reject.Invoke(jsError(err.Error()))
				return
			}
			b, err := json.Marshal(result)
			if err != nil {
				reject.Invoke(jsError(err.Error()))
				return
			}
			resolve.Invoke(string(b))
		}()

		return nil
	})

	return js.Global().Get("Promise").New(handler)
}

func jsError(msg string) js.Value {
	return js.Global().Get("Error").New(msg)
}

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
	select {}
}

// aguaraScanContent(content, filename) -> Promise<JSON>
func scanContent(this js.Value, args []js.Value) any {
	if len(args) < 2 {
		return jsError("aguaraScanContent requires 2 arguments: content, filename")
	}
	content := args[0].String()
	filename := args[1].String()

	return newPromise(func() (any, error) {
		return aguara.ScanContent(context.Background(), content, filename)
	})
}

// aguaraScanContentAs(content, filename, toolName) -> Promise<JSON>
func scanContentAs(this js.Value, args []js.Value) any {
	if len(args) < 3 {
		return jsError("aguaraScanContentAs requires 3 arguments: content, filename, toolName")
	}
	content := args[0].String()
	filename := args[1].String()
	toolName := args[2].String()

	return newPromise(func() (any, error) {
		return aguara.ScanContentAs(context.Background(), content, filename, toolName)
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

//go:build js && wasm

package main

import (
	"encoding/json"
	"errors"
	"runtime"
	"strings"
	"syscall/js"
	"testing"
	"time"
)

type promiseResult struct {
	value    js.Value
	rejected bool
}

func awaitPromise(t *testing.T, promise js.Value) promiseResult {
	t.Helper()
	done := make(chan promiseResult, 1)
	resolve := js.FuncOf(func(_ js.Value, args []js.Value) any {
		done <- promiseResult{value: args[0]}
		return nil
	})
	defer resolve.Release()
	reject := js.FuncOf(func(_ js.Value, args []js.Value) any {
		done <- promiseResult{value: args[0], rejected: true}
		return nil
	})
	defer reject.Release()
	promise.Call("then", resolve, reject)
	select {
	case result := <-done:
		return result
	case <-time.After(2 * time.Second):
		t.Fatal("Promise did not settle")
		return promiseResult{}
	}
}

// The non-tiny witness proves collection of the captured closure without
// inspecting runtime internals or allocating a large scan corpus.
type lifetimeWitness [64]byte

func trackedWork(fn func() (any, error)) (func() (any, error), <-chan struct{}) {
	collected := make(chan struct{})
	witness := new(lifetimeWitness)
	runtime.SetFinalizer(witness, func(*lifetimeWitness) { close(collected) })
	return func() (any, error) {
		defer runtime.KeepAlive(witness)
		return fn()
	}, collected
}

func requireCollected(t *testing.T, collected <-chan struct{}) {
	t.Helper()
	for range 5 {
		runtime.GC()
		select {
		case <-collected:
			return
		case <-time.After(200 * time.Millisecond):
		}
	}
	t.Fatal("Promise executor still retains its captured work after completion")
}

func TestNewPromiseReleasesWork(t *testing.T) {
	for _, tc := range []struct {
		name string
		work func() (any, error)
		want string
	}{
		{"success", func() (any, error) { return map[string]string{"status": "ok"}, nil }, ""},
		{"work error", func() (any, error) { return nil, errors.New("scan failed") }, "scan failed"},
		{"marshal error", func() (any, error) { return make(chan int), nil }, "json: unsupported type: chan int"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			work, collected := trackedWork(func() (any, error) {
				calls++
				return tc.work()
			})
			result := awaitPromise(t, newPromise(work))
			if calls != 1 {
				t.Fatalf("work ran %d times, want once", calls)
			}
			if tc.want != "" {
				if !result.rejected || !result.value.InstanceOf(js.Global().Get("Error")) || result.value.Get("message").String() != tc.want {
					t.Fatalf("expected JavaScript Error %q, got %+v", tc.want, result)
				}
			} else if result.rejected || result.value.String() != `{"status":"ok"}` {
				t.Fatalf("expected JSON success, got %+v", result)
			}
			requireCollected(t, collected)
		})
	}
}

func TestNewPromiseWorkCanFinishAfterConstructorReturns(t *testing.T) {
	resume := make(chan struct{})
	work, collected := trackedWork(func() (any, error) {
		<-resume
		return "completed later", nil
	})
	promise := newPromise(work)
	// No event-loop blocking: work remains alive after the executor returns.
	runtime.GC()
	select {
	case <-collected:
		t.Fatal("work collected before it completed")
	default:
	}
	close(resume)
	result := awaitPromise(t, promise)
	if result.rejected || result.value.String() != `"completed later"` {
		t.Fatalf("unexpected deferred result: %+v", result)
	}
	requireCollected(t, collected)
}

func TestNewPromiseReleasesExecutorWhenConstructorThrows(t *testing.T) {
	original := js.Global().Get("Promise")
	js.Global().Set("Promise", js.Global().Get("Function").New("throw new Error('constructor failed')"))
	defer js.Global().Set("Promise", original)
	work, collected := trackedWork(func() (any, error) {
		t.Error("work must not run when the constructor throws")
		return nil, nil
	})
	func() {
		defer func() {
			failure := recover()
			if err, ok := failure.(js.Error); !ok || err.Value.Get("message").String() != "constructor failed" {
				t.Errorf("unexpected constructor failure: %v", failure)
			}
		}()
		newPromise(work)
	}()
	requireCollected(t, collected)
}

func TestScanPromiseEntryPoints(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(js.Value, []js.Value) any
		args []js.Value
	}{
		{"scanContent", scanContent, []js.Value{js.ValueOf("Ordinary documentation."), js.ValueOf("sample.txt")}},
		{"scanContentAs", scanContentAs, []js.Value{js.ValueOf("Ordinary documentation."), js.ValueOf("sample.txt"), js.ValueOf("example-tool")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invalid := tc.call(js.Undefined(), nil).(js.Value)
			if !invalid.InstanceOf(js.Global().Get("Error")) {
				t.Fatal("missing arguments must return a synchronous Error value")
			}
			for range 2 {
				result := awaitPromise(t, tc.call(js.Undefined(), tc.args).(js.Value))
				if result.rejected || !json.Valid([]byte(result.value.String())) || !strings.Contains(result.value.String(), `"findings"`) {
					t.Fatalf("entry point did not return a JSON scan: %+v", result)
				}
			}
		})
	}
}

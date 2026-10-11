// SPDX-License-Identifier: BSD-3-Clause

//go:build js && wasm

package client

import (
	"sync"
	"syscall/js"
)

var tabMu sync.Mutex

// WebLocks is a serialize function for New in a browser: it runs fn while
// holding the lock named name, which every tab of this origin shares (the
// Web Locks API), so that two tabs never refresh at once. A browser without
// the API gets this tab's own lock.
func WebLocks(name string) func(func() error) error {
	return func(fn func() error) error {
		locks := js.Global().Get("navigator").Get("locks")
		if !locks.Truthy() {
			tabMu.Lock()
			defer tabMu.Unlock()
			return fn()
		}
		done := make(chan error, 1)
		var inner js.Func
		outer := js.FuncOf(func(js.Value, []js.Value) any {
			// The lock is held until the promise returned here settles.
			inner = js.FuncOf(func(_ js.Value, a []js.Value) any {
				resolve := a[0]
				go func() {
					err := fn()
					resolve.Invoke()
					done <- err
				}()
				return nil
			})
			return js.Global().Get("Promise").New(inner)
		})
		defer outer.Release()
		locks.Call("request", name, outer)
		err := <-done
		inner.Release()
		return err
	}
}

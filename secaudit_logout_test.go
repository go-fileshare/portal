// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"maps"
	"net/http"
	"testing"
)

// SECAUDIT 2026-11-05: logout clears the cookies in THIS browser only
// (portal.go:370-383); the session is stateless (session.go:85-106) and the
// refresh token inside it is not revoked. A copy of the cookie taken before
// the logout still opens the session, and still buys tokens, until the
// login's own end (lifetime, up to 168h).
func TestSecauditCookieCopyOutlivesLogout(t *testing.T) {
	w := newWorld(t)
	b := w.browser()
	b.login(w)
	stolen := maps.Clone(b.cookies)
	b.do("POST", "/logout", "", true)

	thief := w.browser()
	thief.cookies = stolen
	if res := thief.do("GET", "/session", "", true); res.StatusCode == http.StatusOK {
		t.Fatalf("a cookie copied before logout still opens the session after it: %s", res.Status)
	}
}

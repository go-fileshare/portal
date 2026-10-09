// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

const adminCall = "/fileshare.admin.v1.AdminService/ListShares"

// The whole path: log in, buy a token per server, call both -- and each
// server receives a token addressed to it alone, and nothing of the
// browser's.
func TestLoginRefreshAndCallTwoServers(t *testing.T) {
	w := newWorld(t)
	b := w.browser()
	res := b.login(w)
	if res.StatusCode != http.StatusOK || !strings.Contains(body(res), `url=/console/`) {
		t.Fatalf("callback: %s", res.Status)
	}
	if _, ok := b.cookies[flowCookie]; ok {
		t.Fatal("the flow cookie outlived the callback")
	}
	c := b.cookies[chunkName(0)]
	if c == nil || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" {
		t.Fatalf("session cookie: %+v", c)
	}

	who := readJSON(t, b.do("GET", "/session", "", true))
	if who["subject"] != "alice-sub" || who["name"] != "alice" {
		t.Fatalf("session: %v", who)
	}

	// No token yet: the proxy says to refresh, and does not do it itself.
	res = b.do("POST", "/api/a"+adminCall, "{}", true)
	if res.StatusCode != http.StatusUnauthorized || res.Header.Get("Portal-Refresh") != "a" {
		t.Fatalf("before refresh: %s %q", res.Status, res.Header.Get("Portal-Refresh"))
	}
	if w.idp.refreshN != 0 {
		t.Fatal("the proxy spent the refresh token")
	}

	res = b.do("POST", "/session/refresh", `{"servers":["a","b","a"]}`, true)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("refresh: %s %s", res.Status, body(res))
	}
	res.Body.Close()
	if w.idp.refreshN != 2 {
		t.Fatalf("%d refreshes for two servers", w.idp.refreshN)
	}

	for _, s := range []struct {
		id string
		fs *fakeServer
	}{{"a", w.a}, {"b", w.b}} {
		res := b.do("POST", "/api/"+s.id+adminCall, "{}", true, "Authorization", "Bearer browser-token", "Origin", publicURL)
		got := readJSON(t, res)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("%s: %s %v", s.id, res.Status, got)
		}
		aud := fmt.Sprint(got["aud"])
		if aud != "["+s.fs.resource+"]" {
			t.Fatalf("server %s got a token for %s", s.id, aud)
		}
		if s.fs.lastPath != adminCall {
			t.Fatalf("server %s was asked %s", s.id, s.fs.lastPath)
		}
		for _, h := range []string{"Cookie", requestHeader, "Origin"} {
			if s.fs.last.Get(h) != "" {
				t.Fatalf("server %s received the browser's %s", s.id, h)
			}
		}
		if res.Header.Get("Set-Cookie") != "" {
			t.Fatalf("server %s set a cookie on the portal's origin", s.id)
		}
	}
}

// A refresh token presented twice -- two copies refreshing with the same
// cookie -- ends the grant at a rotating provider; the portal then ends the
// session, and says so, rather than failing every call after.
func TestAReplayedRefreshTokenEndsTheSession(t *testing.T) {
	w := newWorld(t)
	b := w.browser()
	b.login(w)
	stale := map[string]string{}
	for n, c := range b.cookies {
		stale[n] = c.Value
	}
	if res := b.do("POST", "/session/refresh", `{"servers":["a"]}`, true); res.StatusCode != http.StatusOK {
		t.Fatal(res.Status)
	}
	// The other tab, with the cookie from before.
	old := w.browser()
	for n, v := range stale {
		old.cookies[n] = &http.Cookie{Name: n, Value: v}
	}
	res := old.do("POST", "/session/refresh", `{"servers":["a"]}`, true)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay: %s", res.Status)
	}
	if len(old.cookies) != 0 {
		t.Fatalf("the session was not cleared: %v", old.cookies)
	}
	// The family is revoked: the tab that refreshed correctly is out too,
	// which is the price RFC 9700 names; it learns it at its next refresh.
	if res := b.do("POST", "/session/refresh", `{"servers":["a"]}`, true); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after the family was revoked: %s", res.Status)
	}
}

// A provider that does not rotate leaves the refresh token as it was.
func TestARefreshWithoutRotationKeepsTheToken(t *testing.T) {
	w := newWorld(t)
	w.idp.noRotate = true
	b := w.browser()
	b.login(w)
	for range 2 {
		if res := b.do("POST", "/session/refresh", `{"servers":["a","b"]}`, true); res.StatusCode != http.StatusOK {
			t.Fatal(res.Status)
		}
	}
	if res := b.do("POST", "/api/b"+adminCall, "{}", true); res.StatusCode != http.StatusOK {
		t.Fatal(res.Status)
	}
}

// A provider down halfway keeps what was bought, the rotated refresh token
// first among it.
func TestARefreshFailingHalfwayKeepsTheRotatedToken(t *testing.T) {
	w := newWorld(t)
	w.idp.failRefreshFor = w.b.resource
	b := w.browser()
	b.login(w)
	res := b.do("POST", "/session/refresh", `{"servers":["a","b"]}`, true)
	if res.StatusCode != http.StatusBadGateway {
		t.Fatalf("%s", res.Status)
	}
	if res := b.do("POST", "/api/a"+adminCall, "{}", true); res.StatusCode != http.StatusOK {
		t.Fatalf("a after a partial refresh: %s", res.Status)
	}
	w.idp.failRefreshFor = ""
	if res := b.do("POST", "/session/refresh", `{"servers":["b"]}`, true); res.StatusCode != http.StatusOK {
		t.Fatalf("the rotated refresh token was lost: %s", res.Status)
	}
}

func TestRefreshRefusals(t *testing.T) {
	w := newWorld(t)
	b := w.browser()
	if res := b.do("POST", "/session/refresh", `{"servers":["a"]}`, true); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no session: %s", res.Status)
	}
	b.login(w)
	for _, bad := range []string{``, `{}`, `{"servers":[]}`, `{"servers":["zz"]}`, `nope`} {
		if res := b.do("POST", "/session/refresh", bad, true); res.StatusCode != http.StatusBadRequest {
			t.Fatalf("%q: %s", bad, res.Status)
		}
	}
	// A resource the provider does not know is its invalid_target, which is
	// not the end of the grant.
	w.idp.resources = w.idp.resources[:1]
	if res := b.do("POST", "/session/refresh", `{"servers":["b"]}`, true); res.StatusCode != http.StatusBadGateway {
		t.Fatalf("invalid_target: %s", res.Status)
	}
	if res := b.do("GET", "/session", "", true); res.StatusCode != http.StatusOK {
		t.Fatalf("the session ended on invalid_target: %s", res.Status)
	}
}

func TestLogoutClearsAndPointsAtTheProvider(t *testing.T) {
	w := newWorld(t)
	b := w.browser()
	b.login(w)
	got := readJSON(t, b.do("POST", "/logout", "", true))
	end, _ := got["end_session"].(string)
	if !strings.HasPrefix(end, w.idp.issuer+"/logout?x=1&") || !strings.Contains(end, "client_id=portal") {
		t.Fatalf("end_session %q", end)
	}
	if len(b.cookies) != 0 {
		t.Fatalf("cookies left: %v", b.cookies)
	}
	if res := b.do("GET", "/session", "", true); res.StatusCode != http.StatusUnauthorized {
		t.Fatal(res.Status)
	}
	// Logging out without a session is not an error.
	if got := readJSON(t, b.do("POST", "/logout", "", true)); len(got) != 0 {
		t.Fatal(got)
	}
}

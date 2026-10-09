// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// What another page could make a logged-in browser send is refused before
// it is read: no static header, another origin, another site.
func TestCSRFGate(t *testing.T) {
	w := newWorld(t)
	b := w.browser()
	b.login(w)
	b.do("POST", "/session/refresh", `{"servers":["a"]}`, true)
	cases := []struct {
		name  string
		fetch bool
		hdr   []string
	}{
		{"no static header", false, nil},
		{"static header with another value", false, []string{requestHeader, "true"}},
		{"another origin", true, []string{"Origin", "https://evil.example"}},
		{"the right host on another scheme", true, []string{"Origin", "http://portal.test"}},
		{"another site", true, []string{"Sec-Fetch-Site", "cross-site"}},
		{"a sibling host", true, []string{"Sec-Fetch-Site", "same-site"}},
	}
	for _, c := range cases {
		for _, ep := range []struct{ method, path string }{
			{"POST", "/api/a" + adminCall}, {"POST", "/session/refresh"}, {"POST", "/logout"}, {"GET", "/session"},
		} {
			res := b.do(ep.method, ep.path, `{"servers":["a"]}`, c.fetch, c.hdr...)
			if res.StatusCode != http.StatusForbidden {
				t.Errorf("%s, %s %s: %s", c.name, ep.method, ep.path, res.Status)
			}
		}
	}
	if w.a.lastPath != "" {
		t.Fatal("a refused call reached the server")
	}
	// The same-origin, header-carrying call is the one that passes.
	if res := b.do("POST", "/api/a"+adminCall, "{}", true, "Origin", publicURL, "Sec-Fetch-Site", "same-origin"); res.StatusCode != http.StatusOK {
		t.Fatalf("the portal's own call: %s", res.Status)
	}
}

func TestProxyRefusals(t *testing.T) {
	w := newWorld(t)
	b := w.browser()
	if res := b.do("POST", "/api/a"+adminCall, "{}", true); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no session: %s", res.Status)
	}
	b.login(w)
	b.do("POST", "/session/refresh", `{"servers":["a"]}`, true)
	for path, want := range map[string]int{
		"/api/zz" + adminCall:                                  http.StatusNotFound,
		"/api/a/grpc.health.v1.Health/Check":                   http.StatusNotFound,
		"/api/a/fileshare.admin.v1.AdminService/":              http.StatusNotFound,
		"/api/a/fileshare.admin.v1.AdminService/X/../../debug": http.StatusTemporaryRedirect, // cleaned by the mux, to a path refused below
		"/api/a/fileshare.admin.v1.AdminService/X%2F..":        http.StatusNotFound,
		"/api/b" + adminCall:                                   http.StatusUnauthorized, // no token bought for b
	} {
		if res := b.do("POST", path, "{}", true); res.StatusCode != want {
			t.Errorf("%s: %s, want %d", path, res.Status, want)
		}
	}
	if w.a.lastPath != "" {
		t.Fatalf("a refused path reached the server: %s", w.a.lastPath)
	}
	// A token at the edge of its life is not sent.
	w.portal.now = func() time.Time { return time.Now().Add(5*time.Minute - 10*time.Second) }
	if res := b.do("POST", "/api/a"+adminCall, "{}", true); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an expiring token: %s", res.Status)
	}
	w.portal.now = time.Now
	// More than a call may carry.
	big := `{"x":"` + strings.Repeat("a", maxCall) + `"}`
	if res := b.do("POST", "/api/a"+adminCall, big, true); res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("a %d-byte call: %s", len(big), res.Status)
	}
	// The same without a length announced: cut off on the way.
	r := httptest.NewRequest("POST", publicURL+"/api/a"+adminCall, struct{ io.Reader }{strings.NewReader(big)})
	r.ContentLength = -1
	r.Header.Set(requestHeader, "1")
	for _, c := range b.cookies {
		r.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.h.ServeHTTP(rec, r)
	if rec.Code == http.StatusOK {
		t.Fatalf("a %d-byte call without a length went through", len(big))
	}
	// A server that is down.
	w.a.srv.Close()
	if res := b.do("POST", "/api/a"+adminCall, "{}", true); res.StatusCode != http.StatusBadGateway {
		t.Fatalf("a server down: %s", res.Status)
	}
}

func TestCallbackRefusals(t *testing.T) {
	t.Run("no flow", func(t *testing.T) {
		w := newWorld(t)
		if res := w.browser().do("GET", "/callback?code=x&state=y", "", false); res.StatusCode != http.StatusUnauthorized {
			t.Fatal(res.Status)
		}
	})
	t.Run("another state", func(t *testing.T) {
		w := newWorld(t)
		b := w.browser()
		loc := b.do("GET", "/login", "", false).Header.Get("Location")
		nc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		res, err := nc.Get(loc)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		cb, _ := url.Parse(res.Header.Get("Location"))
		q := cb.Query()
		q.Set("state", "forged")
		if res := b.do("GET", "/callback?"+q.Encode(), "", false); res.StatusCode != http.StatusUnauthorized {
			t.Fatal(res.Status)
		}
	})
	t.Run("another issuer", func(t *testing.T) {
		w := newWorld(t)
		b := w.browser()
		// A real code and state, the iss changed: only the iss check
		// stands between this and a session.
		loc := b.do("GET", "/login", "", false).Header.Get("Location")
		nc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		res, err := nc.Get(loc)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		cb, _ := url.Parse(res.Header.Get("Location"))
		q := cb.Query()
		q.Set("iss", "https://evil.example")
		if res := b.do("GET", "/callback?"+q.Encode(), "", false); res.StatusCode != http.StatusUnauthorized {
			t.Fatal(res.Status)
		}
	})
	t.Run("provider error", func(t *testing.T) {
		w := newWorld(t)
		b := w.browser()
		loc, _ := url.Parse(b.do("GET", "/login", "", false).Header.Get("Location"))
		if res := b.do("GET", "/callback?error=access_denied&state="+loc.Query().Get("state"), "", false); res.StatusCode != http.StatusUnauthorized {
			t.Fatal(res.Status)
		}
	})
	t.Run("a code that does not exchange", func(t *testing.T) {
		w := newWorld(t)
		b := w.browser()
		loc, _ := url.Parse(b.do("GET", "/login", "", false).Header.Get("Location"))
		if res := b.do("GET", "/callback?code=never-issued&state="+loc.Query().Get("state"), "", false); res.StatusCode != http.StatusUnauthorized {
			t.Fatal(res.Status)
		}
	})
	t.Run("an answer played twice", func(t *testing.T) {
		// The portal keeps no state, so it cannot remember a flow it
		// has used: the browser's copy is cleared, and a copy kept
		// elsewhere replays. What stops the replay is the provider, at
		// which a code is good once (RFC 6749 §4.1.2).
		w := newWorld(t)
		b := w.browser()
		loc := b.do("GET", "/login", "", false).Header.Get("Location")
		flowC := b.cookies[flowCookie]
		nc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		res, err := nc.Get(loc)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		cb, _ := url.Parse(res.Header.Get("Location"))
		if res := b.do("GET", cb.RequestURI(), "", false); res.StatusCode != http.StatusOK {
			t.Fatal(res.Status)
		}
		again := w.browser()
		again.cookies[flowCookie] = flowC
		if res := again.do("GET", cb.RequestURI(), "", false); res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("the same code twice: %s", res.Status)
		}
		if _, ok := again.cookies[chunkName(0)]; ok {
			t.Fatal("the replay got a session")
		}
	})
	t.Run("an expired flow", func(t *testing.T) {
		w := newWorld(t)
		b := w.browser()
		loc := b.do("GET", "/login", "", false).Header.Get("Location")
		w.portal.now = func() time.Time { return time.Now().Add(flowLifetime + time.Second) }
		if res := b.followIdP(loc); res.StatusCode != http.StatusUnauthorized {
			t.Fatal(res.Status)
		}
	})
	for name, knob := range map[string]func(*testIdP){
		"a nonce from another login":            func(p *testIdP) { p.badNonce = true },
		"no refresh token":                      func(p *testIdP) { p.noRefresh = true },
		"an ID token for two audiences, no azp": func(p *testIdP) { p.extraAud = true },
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			knob(w.idp)
			b := w.browser()
			if res := b.login(w); res.StatusCode != http.StatusUnauthorized {
				t.Fatal(res.Status)
			}
			if _, ok := b.cookies[chunkName(0)]; ok {
				t.Fatal("a session was stored")
			}
		})
	}
}

func TestDiscoveryRefusals(t *testing.T) {
	for name, knob := range map[string]func(*testIdP){
		"an issuer that is not the one asked": func(p *testIdP) { p.wrongIssuer = true },
		"no S256":                             func(p *testIdP) { p.noS256 = true },
	} {
		t.Run(name, func(t *testing.T) {
			idp := newTestIdP(t)
			knob(idp)
			is := &issuerBlock{URL: idp.issuer, ClientID: "portal", secret: "s"}
			if _, err := newProvider(context.Background(), is, publicURL+"/callback", http.DefaultClient); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestSafeReturn(t *testing.T) {
	for in, want := range map[string]string{
		"/console/":             "/console/",
		"/explorer/?p=/a":       "/explorer/?p=/a",
		"":                      "/",
		"https://evil.example/": "/",
		"//evil.example/":       "/",
		"/\\evil.example/":      "/",
		"console":               "/",
		"/a\r\nSet-Cookie: x":   "/",
		"/%zz":                  "/",
	} {
		if got := safeReturn(in); got != want {
			t.Errorf("safeReturn(%q) = %q, want %q", in, got, want)
		}
	}
}

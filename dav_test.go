// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/go-authn/oidc"
)

// fakeDAV stands for a fileshare WebDAV listener: it checks the bearer token
// against its own audience (fileshare's oidc block), and records what came.
type fakeDAV struct {
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []davSeen
}

type davSeen struct {
	method, path, dest, depth, crange string
	header                            http.Header
	body                              int
}

const (
	davAdmin    = "https://fs-d.example/"     // server d's admin API audience
	davAudience = "https://fs-d.example/dav/" // and its WebDAV's
)

func newFakeDAV(t *testing.T, idp *testIdP) *fakeDAV {
	t.Helper()
	f := &fakeDAV{}
	v, err := oidc.New(context.Background(), oidc.Config{Issuer: idp.issuer, Audience: davAudience})
	if err != nil {
		t.Fatal(err)
	}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if _, err := v.Verify(r.Context(), raw); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		n, _ := io.Copy(io.Discard, r.Body)
		f.mu.Lock()
		f.reqs = append(f.reqs, davSeen{r.Method, r.URL.Path, r.Header.Get("Destination"), r.Header.Get("Depth"),
			r.Header.Get("Content-Range"), r.Header.Clone(), int(n)})
		f.mu.Unlock()
		switch r.Method {
		case http.MethodGet:
			// What somebody stored on a share: a page with a script.
			w.Header().Set("Content-Type", "text/html")
			http.SetCookie(w, &http.Cookie{Name: "server", Value: "x"})
			_, _ = io.WriteString(w, "<html><script>fetch('/api/...')</script></html>")
		case "PROPFIND":
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusMultiStatus)
			_, _ = io.WriteString(w, `<?xml version="1.0"?><D:multistatus xmlns:D="DAV:"/>`)
		case http.MethodPut, "MKCOL", "MOVE", "COPY":
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeDAV) last() davSeen {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reqs) == 0 {
		return davSeen{}
	}
	return f.reqs[len(f.reqs)-1]
}

func (f *fakeDAV) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reqs)
}

// davWorld is the usual world plus server d, whose WebDAV has an audience of
// its own; logged in, with tokens bought for d.
func davWorld(t *testing.T) (*world, *fakeDAV, *browser) {
	t.Helper()
	var dav *fakeDAV
	w := newWorld(t, func(w *world, b *strings.Builder) {
		dav = newFakeDAV(t, w.idp)
		w.idp.resources = append(w.idp.resources, davAdmin, davAudience)
		fmt.Fprintf(b, "server \"d\" {\n url = %q\n issuer = %q\n resource = %q\n dav_url = %q\n dav_resource = %q\n}\n",
			w.a.srv.URL, w.idp.issuer, davAdmin, dav.srv.URL, davAudience)
	})
	b := w.browser()
	b.login(w)
	if res := b.do("POST", "/session/refresh", `{"servers":["d"]}`, true); res.StatusCode != http.StatusOK {
		t.Fatalf("refresh: %s %s", res.Status, body(res))
	}
	return w, dav, b
}

func TestDAVPassesWithItsOwnToken(t *testing.T) {
	w, dav, b := davWorld(t)
	// The session view says which servers the explorer can browse.
	got := readJSON(t, b.do("GET", "/session", "", true))
	if !strings.Contains(fmt.Sprint(got["servers"]), "dav:true") {
		t.Fatalf("servers %v", got["servers"])
	}
	res := b.do("PROPFIND", "/dav/d/photos/", `<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>`, true, "Depth", "1")
	if res.StatusCode != http.StatusMultiStatus {
		t.Fatalf("PROPFIND: %s %s", res.Status, body(res))
	}
	if s := dav.last(); s.method != "PROPFIND" || s.path != "/photos/" || s.depth != "1" || s.header.Get("Cookie") != "" || s.header.Get(requestHeader) != "" {
		t.Fatalf("%+v", s)
	}
	// Its token is WebDAV's audience, which is not the admin API's: the
	// fake verifies exactly that, and refused nothing.
	if audOf(t, w.portal.sessions.read(cookieReq(b)).Tokens["d"+davKey].Token) != davAudience {
		t.Fatal("the WebDAV token is not addressed to WebDAV")
	}

	// A piece of an upload, then the move to its name.
	res = b.do("PUT", "/dav/d/photos/big.part", strings.Repeat("x", 1000), true, "Content-Range", "bytes 0-999/5000")
	if res.StatusCode != http.StatusCreated || dav.last().crange != "bytes 0-999/5000" || dav.last().body != 1000 {
		t.Fatalf("PUT: %s %+v", res.Status, dav.last())
	}
	res = b.do("MOVE", "/dav/d/photos/big.part", "", true, "Destination", publicURL+"/dav/d/photos/big.bin")
	if res.StatusCode != http.StatusCreated || dav.last().dest != dav.srv.URL+"/photos/big.bin" {
		t.Fatalf("MOVE: %s, destination %q", res.Status, dav.last().dest)
	}
	// A relative Destination is the same thing.
	res = b.do("COPY", "/dav/d/photos/a", "", true, "Destination", "/dav/d/photos/b")
	if res.StatusCode != http.StatusCreated || dav.last().dest != dav.srv.URL+"/photos/b" {
		t.Fatalf("COPY: %s, destination %q", res.Status, dav.last().dest)
	}
	if res := b.do("MKCOL", "/dav/d/photos/new/", "", true); res.StatusCode != http.StatusCreated {
		t.Fatal(res.Status)
	}
	if res := b.do("DELETE", "/dav/d/photos/old", "", true); res.StatusCode != http.StatusNoContent {
		t.Fatal(res.Status)
	}
}

// What a share holds is served as an inert attachment: a page with a
// script, downloaded through the portal, never runs as the portal.
func TestDAVDownloadsAreInert(t *testing.T) {
	_, _, b := davWorld(t)
	// A download is a navigation: no static header, and it still passes.
	res := b.do("GET", "/dav/d/photos/evil.html", "", false, "Sec-Fetch-Site", "same-origin")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET: %s", res.Status)
	}
	h := res.Header
	for k, want := range map[string]string{
		"Content-Type":            "application/octet-stream",
		"Content-Disposition":     "attachment; filename=evil.html",
		"X-Content-Type-Options":  "nosniff",
		"Content-Security-Policy": "sandbox; default-src 'none'",
	} {
		if got := h.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	// One policy, not the portal's and the server's side by side.
	if n := len(h.Values("Content-Security-Policy")); n != 1 {
		t.Errorf("%d Content-Security-Policy headers: %q", n, h.Values("Content-Security-Policy"))
	}
	if h.Get("Set-Cookie") != "" {
		t.Error("a server's cookie reached the portal's origin")
	}
	// HEAD too.
	if res := b.do("HEAD", "/dav/d/photos/evil.html", "", false); res.Header.Get("Content-Disposition") == "" {
		t.Error("HEAD is not an attachment")
	}
}

func TestDAVRefusals(t *testing.T) {
	w, dav, b := davWorld(t)
	n := dav.count()
	for _, c := range []struct {
		name, method, path string
		fetch              bool
		hdr                []string
		want               int
	}{
		{"a PUT without the static header", "PUT", "/dav/d/x", false, nil, 403},
		{"a DELETE from another origin", "DELETE", "/dav/d/x", true, []string{"Origin", "https://evil.example"}, 403},
		{"a GET another site starts", "GET", "/dav/d/x", false, []string{"Sec-Fetch-Site", "cross-site"}, 403},
		{"a GET a sibling site starts", "GET", "/dav/d/x", false, []string{"Sec-Fetch-Site", "same-site"}, 403},
		{"LOCK", "LOCK", "/dav/d/x", true, nil, 405},
		{"PROPPATCH", "PROPPATCH", "/dav/d/x", true, nil, 405},
		{"PROPFIND Depth infinity", "PROPFIND", "/dav/d/", true, []string{"Depth", "infinity"}, 403},
		{"PROPFIND without Depth", "PROPFIND", "/dav/d/", true, nil, 403},
		{"a server with no WebDAV", "GET", "/dav/a/x", false, nil, 404},
		{"an unknown server", "GET", "/dav/zz/x", false, nil, 404},
		{"a dot-dot", "GET", "/dav/d/photos/%2e%2e/x", false, nil, 400},
		{"a MOVE to another server", "MOVE", "/dav/d/x", true, []string{"Destination", publicURL + "/dav/a/x"}, 400},
		{"a MOVE to another host", "MOVE", "/dav/d/x", true, []string{"Destination", "https://evil.example/dav/d/x"}, 400},
		{"a MOVE out of /dav", "MOVE", "/dav/d/x", true, []string{"Destination", publicURL + "/api/d/x"}, 400},
		{"a MOVE up with ..", "MOVE", "/dav/d/x", true, []string{"Destination", publicURL + "/dav/d/photos/../../etc"}, 400},
		{"a MOVE with no Destination", "MOVE", "/dav/d/x", true, nil, 400},
		{"a MOVE to the root", "MOVE", "/dav/d/x", true, []string{"Destination", "/dav/d/"}, 400},
		{"a MOVE with a query", "MOVE", "/dav/d/x", true, []string{"Destination", "/dav/d/y?z=1"}, 400},
	} {
		if res := b.do(c.method, c.path, "", c.fetch, c.hdr...); res.StatusCode != c.want {
			t.Errorf("%s: %s, want %d", c.name, res.Status, c.want)
		}
	}
	// A piece larger than 16 MiB.
	big := strings.Repeat("x", maxPiece+1)
	if res := b.do("PUT", "/dav/d/x", big, true); res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("a large PUT: %s", res.Status)
	}
	if dav.count() != n {
		t.Fatalf("%d refused requests reached the server", dav.count()-n)
	}
	// No session, and no token for d: the portal says to refresh.
	if res := w.browser().do("GET", "/dav/d/x", "", false); res.StatusCode != http.StatusUnauthorized {
		t.Fatal(res.Status)
	}
	b.do("POST", "/session/refresh", `{"servers":["a"]}`, true) // d's tokens dropped
	if res := b.do("GET", "/dav/d/x", "", false); res.StatusCode != http.StatusUnauthorized || res.Header.Get("Portal-Refresh") != "d" {
		t.Fatalf("%s %q", res.Status, res.Header.Get("Portal-Refresh"))
	}
}

func cookieReq(b *browser) *http.Request {
	r := httptest.NewRequest("GET", publicURL, nil)
	for _, c := range b.cookies {
		r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	return r
}

func TestDAVTargets(t *testing.T) {
	dir := t.TempDir()
	cert, _ := selfSigned(t, dir)
	if _, err := newDAV([]serverBlock{{ID: "a", DAVURL: "https://a", CAFile: cert}}); err != nil {
		t.Fatal(err)
	}
	for _, s := range []serverBlock{
		{ID: "a", DAVURL: "https://a", CAFile: filepath.Join(dir, "none.pem")},
		{ID: "a", DAVURL: "https://a", CAFile: filepath.Join(dir, "key.pem")},
		{ID: "a", DAVURL: "%zz"},
	} {
		if _, err := newDAV([]serverBlock{s}); err == nil {
			t.Errorf("%+v accepted", s)
		}
	}
}

// A WebDAV server that does not answer: 502, inert like every /dav answer.
func TestDAVServerDown(t *testing.T) {
	_, dav, b := davWorld(t)
	dav.srv.Close()
	res := b.do("PROPFIND", "/dav/d/photos/", "", true, "Depth", "0")
	if res.StatusCode != http.StatusBadGateway || res.Header.Get("Content-Security-Policy") != "sandbox; default-src 'none'" {
		t.Fatalf("%s %v", res.Status, res.Header)
	}
}

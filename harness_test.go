// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-authn/oidc"
)

const publicURL = "https://portal.test"

// fakeServer stands for a fileshare server's admin web listener: it verifies
// the bearer token exactly as fileshare does (go-authn/oidc, its own
// audience), and says what it received.
type fakeServer struct {
	srv      *httptest.Server
	resource string
	last     http.Header
	lastPath string
}

func newFakeServer(t *testing.T, idp *testIdP) *fakeServer {
	t.Helper()
	f := &fakeServer{}
	var v *oidc.Verifier
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.last, f.lastPath = r.Header.Clone(), r.URL.Path
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		tok, err := v.Verify(r.Context(), raw)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, err.Error())
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "server", Value: "x"})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": tok.Subject(), "aud": tok.Audience(), "path": r.URL.Path})
	}))
	t.Cleanup(f.srv.Close)
	f.resource = f.srv.URL
	var err error
	v, err = oidc.New(context.Background(), oidc.Config{Issuer: idp.issuer, Audience: f.resource})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// world is an IdP, two servers, and a portal in front of them.
type world struct {
	t      *testing.T
	idp    *testIdP
	a, b   *fakeServer
	portal *portal
	h      http.Handler
	cfg    *config
	dir    string
}

type worldOpt func(w *world, extra *strings.Builder)

func newWorld(t *testing.T, opts ...worldOpt) *world {
	t.Helper()
	w := &world{t: t, idp: newTestIdP(t), dir: t.TempDir()}
	w.idp.redirect = publicURL + "/callback"
	w.a, w.b = newFakeServer(t, w.idp), newFakeServer(t, w.idp)
	w.idp.resources = []string{w.a.resource, w.b.resource}
	writeSecret(t, filepath.Join(w.dir, "session.key"), strings.Repeat("k", 32))
	writeSecret(t, filepath.Join(w.dir, "client.secret"), w.idp.secret+"\n")
	ui := filepath.Join(w.dir, "console")
	_ = os.MkdirAll(ui, 0o755)
	_ = os.WriteFile(filepath.Join(ui, "index.html"), []byte("<!doctype html>console"), 0o644)
	var extra strings.Builder
	for _, o := range opts {
		o(w, &extra)
	}
	cfgText := fmt.Sprintf(`
listen     = "127.0.0.1:0"
public_url = %q
session { key_files = ["session.key"] }
issuer %q {
  client_id          = "portal"
  client_secret_file = "client.secret"
}
server "a" {
  label    = "A"
  url      = %q
  issuer   = %q
  resource = %q
}
server "b" {
  url      = %q
  issuer   = %q
  resource = %q
}
ui "console" { dir = %q }
%s`, publicURL, w.idp.issuer, w.a.srv.URL, w.idp.issuer, w.a.resource,
		w.b.srv.URL, w.idp.issuer, w.b.resource, ui, extra.String())
	path := filepath.Join(w.dir, "portal.hcl")
	if err := os.WriteFile(path, []byte(cfgText), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	w.cfg = cfg
	p, err := newPortal(context.Background(), cfg, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	p.logf = t.Logf
	w.portal, w.h = p, p.handler()
	return w
}

func writeSecret(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// browser keeps cookies the way a browser would for the portal's origin --
// Secure ones included, since the test talks to the handler directly.
type browser struct {
	t       *testing.T
	h       http.Handler
	cookies map[string]*http.Cookie
}

func (w *world) browser() *browser {
	return &browser{t: w.t, h: w.h, cookies: map[string]*http.Cookie{}}
}

// do sends a request to the portal. fetch adds what the portal's own pages
// add: the static header.
func (b *browser) do(method, target string, body string, fetch bool, hdr ...string) *http.Response {
	b.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, publicURL+target, rd)
	if fetch {
		r.Header.Set(requestHeader, "1")
		r.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	for _, c := range b.cookies {
		r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	rec := httptest.NewRecorder()
	b.h.ServeHTTP(rec, r)
	res := rec.Result()
	for _, c := range res.Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c
		}
	}
	return res
}

// login runs the code flow through the test IdP and returns the callback's
// response.
func (b *browser) login(w *world) *http.Response {
	b.t.Helper()
	res := b.do("GET", "/login?return=/console/", "", false)
	if res.StatusCode != http.StatusFound {
		b.t.Fatalf("login: %s", res.Status)
	}
	return b.followIdP(res.Header.Get("Location"))
}

// followIdP visits the IdP's authorization endpoint and brings its answer
// back to the portal's callback.
func (b *browser) followIdP(auth string) *http.Response {
	b.t.Helper()
	nc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := nc.Get(auth)
	if err != nil {
		b.t.Fatal(err)
	}
	res.Body.Close()
	cb, err := url.Parse(res.Header.Get("Location"))
	if err != nil || res.StatusCode != http.StatusFound {
		b.t.Fatalf("idp: %s %v", res.Status, err)
	}
	return b.do("GET", cb.RequestURI(), "", false)
}

func readJSON(t *testing.T, res *http.Response) map[string]any {
	t.Helper()
	defer res.Body.Close()
	var m map[string]any
	if err := json.NewDecoder(res.Body).Decode(&m); err != nil {
		t.Fatalf("%s: %v", res.Status, err)
	}
	return m
}

func body(res *http.Response) string {
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return string(b)
}

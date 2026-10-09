// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSealer(t *testing.T) {
	k1, k2 := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	old, _ := newSealer([][]byte{k1})
	both, err := newSealer([][]byte{k2, k1})
	if err != nil {
		t.Fatal(err)
	}
	v := old.seal("n", []byte("hello"))
	// A key replaced: the new one seals, the old one still opens.
	if got, err := both.open("n", v); err != nil || string(got) != "hello" {
		t.Fatalf("old key: %q %v", got, err)
	}
	if w := both.seal("n", []byte("x")); !strings.HasPrefix(mustDecode(t, w), string(both.keys[0].id[:])) {
		t.Fatal("the first key did not seal")
	}
	if _, err := old.open("n", both.seal("n", []byte("x"))); err == nil {
		t.Fatal("a key that was never given opened a value")
	}
	// Sealed for one cookie, it is nothing in another.
	if _, err := old.open("other", v); err == nil {
		t.Fatal("opened under another name")
	}
	raw := []byte(mustDecode(t, v))
	raw[len(raw)-1] ^= 1
	if _, err := old.open("n", base64.RawURLEncoding.EncodeToString(raw)); err == nil {
		t.Fatal("a changed value opened")
	}
	for _, bad := range []string{"", "!!", "AAAA"} {
		if _, err := old.open("n", bad); err == nil {
			t.Fatalf("%q opened", bad)
		}
	}
	for _, keys := range [][][]byte{nil, {[]byte("short")}, {k1, k1}} {
		if _, err := newSealer(keys); err == nil {
			t.Fatalf("keys %v accepted", keys)
		}
	}
}

func mustDecode(t *testing.T, s string) string {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestReadKey(t *testing.T) {
	dir := t.TempDir()
	raw := bytes.Repeat([]byte{7}, 32)
	for name, content := range map[string]string{
		"raw": string(raw), "std": base64.StdEncoding.EncodeToString(raw) + "\n",
		"url": base64.RawURLEncoding.EncodeToString(raw),
	} {
		p := filepath.Join(dir, name)
		writeSecret(t, p, content)
		if k, err := readKey(p); err != nil || !bytes.Equal(k, raw) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	short := filepath.Join(dir, "short")
	writeSecret(t, short, "abc")
	if _, err := readKey(short); err == nil {
		t.Fatal("a short key was read")
	}
	if _, err := readKey(filepath.Join(dir, "none")); err == nil {
		t.Fatal("a missing file was read")
	}
	if osHasModeBits {
		open := filepath.Join(dir, "open")
		_ = os.WriteFile(open, raw, 0o644)
		if _, err := readKey(open); err == nil {
			t.Fatal("a key others may read was accepted")
		}
	}
	if _, err := readKey(dir); err == nil {
		t.Fatal("a directory was read as a key")
	}
	if secretModeTooOpen(0o600) || osHasModeBits && !secretModeTooOpen(0o604) {
		t.Fatal("secretModeTooOpen")
	}
}

// A session for many servers spreads over several cookies, and comes back
// whole; one that would need more than a browser keeps is refused, and
// shrinking clears the chunks it no longer needs.
func TestSessionChunks(t *testing.T) {
	s, _ := newSealer([][]byte{bytes.Repeat([]byte{1}, 32)})
	now := time.Now()
	ss := &sessions{sealer: s, now: func() time.Time { return now }, limit: maxChunks * chunkSize}
	big := &session{Issuer: "i", Subject: "s", Expires: now.Add(time.Hour), Refresh: "rt", Tokens: map[string]accessToken{}}
	for i := range 8 {
		big.Tokens[fmt.Sprint(i)] = accessToken{Token: strings.Repeat("t", 1000), Expires: now}
	}
	rec := httptest.NewRecorder()
	if err := ss.write(rec, httptest.NewRequest("GET", "/", nil), big); err != nil {
		t.Fatal(err)
	}
	cs := rec.Result().Cookies()
	if len(cs) < 3 {
		t.Fatalf("%d cookies for a %d-token session", len(cs), len(big.Tokens))
	}
	r := httptest.NewRequest("GET", "/", nil)
	for _, c := range cs {
		if len(c.Name)+len(c.Value) > 4096 {
			t.Fatalf("%s is %d bytes", c.Name, len(c.Name)+len(c.Value))
		}
		r.AddCookie(c)
	}
	got := ss.read(r)
	if got == nil || len(got.Tokens) != 8 {
		t.Fatalf("read back: %+v", got)
	}
	// Shrunk: the chunks past the new end are cleared.
	rec = httptest.NewRecorder()
	small := &session{Issuer: "i", Subject: "s", Expires: now.Add(time.Hour)}
	if err := ss.write(rec, r, small); err != nil {
		t.Fatal(err)
	}
	var cleared int
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 {
			cleared++
		}
	}
	if cleared != len(cs)-1 {
		t.Fatalf("%d of %d stale chunks cleared", cleared, len(cs)-1)
	}
	// Too large.
	for i := range 60 {
		big.Tokens[fmt.Sprint("x", i)] = accessToken{Token: strings.Repeat("t", 1000)}
	}
	if err := ss.write(httptest.NewRecorder(), r, big); err == nil {
		t.Fatal("a session larger than the cookies was written")
	}
	// Expired, or garbage, is no session.
	now = now.Add(2 * time.Hour)
	if ss.read(r) != nil {
		t.Fatal("an expired session was read")
	}
	bad := httptest.NewRequest("GET", "/", nil)
	bad.AddCookie(&http.Cookie{Name: chunkName(0), Value: "garbage"})
	if ss.read(bad) != nil || ss.read(httptest.NewRequest("GET", "/", nil)) != nil {
		t.Fatal("garbage was read as a session")
	}
	ok := httptest.NewRequest("GET", "/", nil)
	ok.AddCookie(&http.Cookie{Name: chunkName(0), Value: s.seal(sessionCookie, []byte("not json"))})
	if ss.read(ok) != nil {
		t.Fatal("a sealed non-session was read")
	}
	fl := httptest.NewRequest("GET", "/", nil)
	fl.AddCookie(&http.Cookie{Name: flowCookie, Value: s.seal(flowCookie, []byte("not json"))})
	if ss.takeFlow(httptest.NewRecorder(), fl) != nil {
		t.Fatal("a sealed non-flow was read")
	}
	fl = httptest.NewRequest("GET", "/", nil)
	fl.AddCookie(&http.Cookie{Name: flowCookie, Value: "garbage"})
	if ss.takeFlow(httptest.NewRecorder(), fl) != nil {
		t.Fatal("garbage was read as a flow")
	}
}

// Too many servers at once: refused, and the refresh token -- perhaps
// rotated -- is kept.
func TestRefreshTooManyServers(t *testing.T) {
	w := newWorld(t, func(w *world, b *strings.Builder) {
		for i := range 20 {
			fmt.Fprintf(b, "server \"x%d\" {\n url = %q\n issuer = %q\n resource = %q\n}\n", i, w.a.srv.URL, w.idp.issuer, w.a.resource)
		}
	})
	b := w.browser()
	b.login(w)
	var ids []string
	for i := range 20 {
		ids = append(ids, fmt.Sprintf("%q", fmt.Sprint("x", i)))
	}
	res := b.do("POST", "/session/refresh", `{"servers":[`+strings.Join(ids, ",")+`]}`, true)
	if res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("%s", res.Status)
	}
	if res := b.do("POST", "/session/refresh", `{"servers":["a"]}`, true); res.StatusCode != http.StatusOK {
		t.Fatalf("after: %s — the rotated refresh token was lost", res.Status)
	}
}

func TestIssuerChooser(t *testing.T) {
	other := newTestIdP(t)
	w := newWorld(t, func(w *world, b *strings.Builder) {
		other.redirect = publicURL + "/callback"
		writeSecret(t, filepath.Join(w.dir, "other.secret"), other.secret)
		fmt.Fprintf(b, "issuer %q {\n client_id = \"portal\"\n client_secret_file = \"other.secret\"\n}\n", other.issuer)
	})
	b := w.browser()
	res := b.do("GET", "/login?return=/console/", "", false)
	page := body(res)
	if res.StatusCode != http.StatusOK || !strings.Contains(page, "issuer=") || !strings.Contains(page, "return=%2Fconsole%2F") {
		t.Fatalf("%s %s", res.Status, page)
	}
	res = b.do("GET", "/login?issuer="+w.idp.issuer, "", false)
	if res.StatusCode != http.StatusFound {
		t.Fatal(res.Status)
	}
	if res := b.followIdP(res.Header.Get("Location")); res.StatusCode != http.StatusOK {
		t.Fatal(res.Status)
	}
	// Servers of the other issuer are listed, and not reachable from here.
	got := readJSON(t, b.do("GET", "/session", "", true))
	if fmt.Sprint(got["servers"]) == "" {
		t.Fatal(got)
	}
}

func TestStatic(t *testing.T) {
	w := newWorld(t)
	dir := w.cfg.UIs[0].Dir
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte("wasm"))
	_ = zw.Close()
	_ = os.WriteFile(filepath.Join(dir, "main.wasm"), []byte("wasm"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "main.wasm.gz"), gz.Bytes(), 0o644)
	_ = os.Mkdir(filepath.Join(dir, "sub"), 0o755)
	b := w.browser()

	if res := b.do("GET", "/", "", false); res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/console/" {
		t.Fatal(res.Status, res.Header.Get("Location"))
	}
	if res := b.do("GET", "/console", "", false); res.StatusCode != http.StatusMovedPermanently {
		t.Fatal(res.Status)
	}
	res := b.do("GET", "/console/", "", false)
	if res.StatusCode != http.StatusOK || !strings.Contains(body(res), "console") || res.Header.Get("Cache-Control") != "no-cache" {
		t.Fatal(res.Status)
	}
	if csp := res.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("csp %q", csp)
	}
	res = b.do("GET", "/console/main.wasm", "", false, "Accept-Encoding", "br, gzip;q=0.8")
	if res.Header.Get("Content-Encoding") != "gzip" || res.Header.Get("Content-Type") != "application/wasm" {
		t.Fatalf("%v", res.Header)
	}
	for _, ae := range []string{"", "gzip;q=0", "br"} {
		res = b.do("GET", "/console/main.wasm", "", false, "Accept-Encoding", ae)
		if res.Header.Get("Content-Encoding") != "" || body(res) != "wasm" {
			t.Fatalf("%q: %v", ae, res.Header)
		}
	}
	for _, p := range []string{"/explorer/", "/console/none", "/console/sub", "/nothing"} {
		if res := b.do("GET", p, "", false); res.StatusCode != http.StatusNotFound {
			t.Errorf("%s: %s", p, res.Status)
		}
	}
	if res := b.do("PUT", "/console/x", "", false); res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatal(res.Status)
	}
	if newStatic(nil).first != "" {
		t.Fatal()
	}
	rec := httptest.NewRecorder()
	newStatic(nil).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatal(rec.Code)
	}
	// serveFile refuses what it cannot seek.
	if serveFile(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil), noSeekFS{}, "f", "f", "") {
		t.Fatal("served an unseekable file")
	}
}

type noSeekFS struct{}

func (noSeekFS) Open(string) (fs.File, error) { return noSeek{}, nil }

type noSeek struct{}

func (noSeek) Stat() (fs.FileInfo, error) { return regular{}, nil }
func (noSeek) Read([]byte) (int, error)   { return 0, nil }
func (noSeek) Close() error               { return nil }

type regular struct{ fs.FileInfo }

func (regular) Mode() fs.FileMode { return 0 }

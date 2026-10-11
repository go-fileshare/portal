// SPDX-License-Identifier: BSD-3-Clause

//go:build e2e

package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The explorer's path, end to end: a real fileshare's WebDAV, behind the
// portal, with a token addressed to WebDAV (the oidc block's audience). A
// listing, an upload in pieces (fileshare v0.29.0 appends at the end), the
// move to its name, and a download that comes back as an inert attachment.
func TestE2EDAVThroughThePortal(t *testing.T) {
	bin := os.Getenv("FILESHARE")
	if bin == "" {
		t.Skip("FILESHARE names the fileshare binary to test against")
	}
	idp := newTestIdP(t)
	idp.redirect = publicURL + "/callback"
	dir := t.TempDir()
	cert, key := selfSigned(t, dir)
	a := startFileshare(t, bin, idp, "A", "https://fs-a.test/", cert, key)
	idp.resources = []string{a.audience, a.audience + "dav"}

	writeSecret(t, filepath.Join(dir, "session.key"), strings.Repeat("k", 32))
	writeSecret(t, filepath.Join(dir, "client.secret"), idp.secret)
	cfgText := fmt.Sprintf(`
listen     = "127.0.0.1:0"
public_url = %q
session { key_files = ["session.key"] }
issuer %q {
  client_id          = "portal"
  client_secret_file = "client.secret"
}
server "a" {
  url          = "https://%s"
  issuer       = %q
  resource     = %q
  ca_file      = %q
  dav_url      = "https://%s"
  dav_resource = %q
}
`, publicURL, idp.issuer, a.addr, idp.issuer, a.audience, cert, a.dav, a.audience+"dav")
	path := filepath.Join(dir, "portal.hcl")
	_ = os.WriteFile(path, []byte(cfgText), 0o644)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	p, err := newPortal(context.Background(), cfg, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	p.logf = t.Logf
	w := &world{t: t, idp: idp, portal: p, h: p.handler(), cfg: cfg}
	br := w.browser()
	if res := br.login(w); res.StatusCode != http.StatusOK {
		t.Fatalf("login: %s", res.Status)
	}
	if res := br.do("POST", "/session/refresh", `{"servers":["a"]}`, true); res.StatusCode != http.StatusOK {
		t.Fatalf("refresh: %s %s", res.Status, body(res))
	}

	res := br.do("PROPFIND", "/dav/a/files/", `<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>`, true, "Depth", "1")
	if got := body(res); res.StatusCode != http.StatusMultiStatus || !strings.Contains(got, "/files/") {
		t.Fatalf("PROPFIND: %s %s", res.Status, got)
	}

	want := bytes.Repeat([]byte("<html><script>alert(1)</script>"), 100_000) // 3.1 MB: three pieces
	const piece = 1 << 20
	if res := br.do("PUT", "/dav/a/files/page.part", "", true); res.StatusCode != http.StatusCreated {
		t.Fatalf("empty PUT: %s %s", res.Status, body(res))
	}
	for off := 0; off < len(want); off += piece {
		end := min(off+piece, len(want)) - 1
		rng := fmt.Sprintf("bytes %d-%d/%d", off, end, len(want))
		if res := br.do("PUT", "/dav/a/files/page.part", string(want[off:end+1]), true, "Content-Range", rng); res.StatusCode != http.StatusNoContent {
			t.Fatalf("%s: %s %s", rng, res.Status, body(res))
		}
	}
	if res := br.do("MOVE", "/dav/a/files/page.part", "", true, "Destination", publicURL+"/dav/a/files/page.html"); res.StatusCode != http.StatusCreated {
		t.Fatalf("MOVE: %s %s", res.Status, body(res))
	}
	if got, err := os.ReadFile(filepath.Join(a.files, "page.html")); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("on disk: %d bytes, %v", len(got), err)
	}

	// The download: the same bytes, as an attachment nobody's browser runs.
	res = br.do("GET", "/dav/a/files/page.html", "", false, "Sec-Fetch-Site", "same-origin")
	got := []byte(body(res))
	if res.StatusCode != http.StatusOK || !bytes.Equal(got, want) {
		t.Fatalf("GET: %s, %d bytes", res.Status, len(got))
	}
	if res.Header.Get("Content-Type") != "application/octet-stream" ||
		!strings.HasPrefix(res.Header.Get("Content-Disposition"), "attachment") ||
		res.Header.Get("Content-Security-Policy") != "sandbox; default-src 'none'" {
		t.Fatalf("not inert: %v", res.Header)
	}
}

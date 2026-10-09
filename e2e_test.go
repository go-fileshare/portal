// SPDX-License-Identifier: BSD-3-Clause

//go:build e2e

package main

// The portal in front of two REAL fileshare servers -- the released binary,
// FILESHARE=/path/to/fileshare -- each with its admin API over HTTPS for
// OIDC tokens (fileshare v0.28.0), and the test provider of idp_test.go.
//
//	go install github.com/go-fileshare/fileshare@v0.28.1
//	FILESHARE=$(go env GOPATH)/bin/fileshare go test -tags e2e -run E2E -v .

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

type realServer struct {
	addr, audience, data string
	out                  *lockedBuffer
}

type lockedBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

var adminLine = regexp.MustCompile(`https://(127\.0\.0\.1:\d+) — the admin API, for OIDC tokens`)

// startFileshare runs the binary with an admin web listener trusting idp for
// audience, and returns its address once it says it is serving.
func startFileshare(t *testing.T, bin string, idp *testIdP, name, audience, cert, key string) *realServer {
	t.Helper()
	dir := t.TempDir()
	// A unix socket path must be short; t.TempDir under /tmp on Linux is.
	sock, err := os.MkdirTemp("", "fs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sock) })
	roots := filepath.Join(dir, "roots")
	_ = os.MkdirAll(filepath.Join(roots, "data"), 0o755)
	writeSecret(t, filepath.Join(dir, "alice.pw"), "correct horse battery staple\n")
	cfg := fmt.Sprintf(`name = %q
user "alice" { password_file = %q }
tls {
  cert_file = %q
  key_file  = %q
}
serve "webdav" { addr = "127.0.0.1:0" }
admin {
  listen       = "unix://%s/admin.sock"
  state_file   = %q
  source_roots = [%q]
  web {
    listen = "127.0.0.1:0"
    issuer %q {
      audience = %q
      groups   = ["fileshare-admins"]
    }
  }
}
`, name, filepath.Join(dir, "alice.pw"), cert, key, sock, filepath.Join(dir, "shares.json"), roots, idp.issuer, audience)
	path := filepath.Join(dir, "fileshare.hcl")
	if err := os.WriteFile(path, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bin, "serve", "--config", path)
	out := &lockedBuffer{}
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = io.MultiWriter(out, pw), io.MultiWriter(out, pw)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = cmd.Wait(); pw.Close() })
	found := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			if m := adminLine.FindStringSubmatch(sc.Text()); m != nil {
				found <- m[1]
			}
		}
	}()
	select {
	case addr := <-found:
		return &realServer{addr: addr, audience: audience, data: filepath.Join(roots, "data"), out: out}
	case <-time.After(20 * time.Second):
		t.Fatalf("%s never served its admin API:\n%s", name, out)
	}
	return nil
}

func TestE2ETwoRealServers(t *testing.T) {
	bin := os.Getenv("FILESHARE")
	if bin == "" {
		t.Skip("FILESHARE names the fileshare binary to test against")
	}
	idp := newTestIdP(t)
	idp.redirect = publicURL + "/callback"
	dir := t.TempDir()
	cert, key := selfSigned(t, dir)
	a := startFileshare(t, bin, idp, "A", "https://fs-a.test/", cert, key)
	b := startFileshare(t, bin, idp, "B", "https://fs-b.test/", cert, key)
	idp.resources = []string{a.audience, b.audience}

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
  url      = "https://%s"
  issuer   = %q
  resource = %q
  ca_file  = %q
}
server "b" {
  url      = "https://%s"
  issuer   = %q
  resource = %q
  ca_file  = %q
}
`, publicURL, idp.issuer, a.addr, idp.issuer, a.audience, cert, b.addr, idp.issuer, b.audience, cert)
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
	if res := br.do("POST", "/session/refresh", `{"servers":["a","b"]}`, true); res.StatusCode != http.StatusOK {
		t.Fatalf("refresh: %s %s", res.Status, body(res))
	}

	// Each real server answers, with the token the portal bought for it.
	for _, id := range []string{"a", "b"} {
		res := br.do("POST", "/api/"+id+adminCall, "{}", true)
		got := body(res)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("%s ListShares: %s %s", id, res.Status, got)
		}
		t.Logf("%s ListShares: %s", id, got)
	}

	// A share created on A through the portal is on A, and not on B.
	create := fmt.Sprintf(`{"name":"data","directory":%q,"grants":[{"subject":{"user":"alice"},"access":"ACCESS_WRITE"}]}`, a.data)
	res := br.do("POST", "/api/a/fileshare.admin.v1.AdminService/CreateShare", create, true)
	if got := body(res); res.StatusCode != http.StatusOK {
		t.Fatalf("CreateShare on a: %s %s", res.Status, got)
	}
	for id, want := range map[string]bool{"a": true, "b": false} {
		got := body(br.do("POST", "/api/"+id+adminCall, "{}", true))
		if strings.Contains(got, `"name":"data"`) != want {
			t.Errorf("%s ListShares after creating on a: %s", id, got)
		}
	}

	// The audit names who made the change as fileshare saw it -- issuer and
	// subject -- on A, which changed, and nobody on B, which did not.
	if !strings.Contains(a.out.String(), "oidc="+idp.issuer+" alice-sub") {
		t.Errorf("a's audit does not name the caller:\n%s", a.out)
	}
	if strings.Contains(b.out.String(), "oidc=") {
		t.Errorf("b audited a change it never received:\n%s", b.out)
	}

	// A's token at B: refused by B itself. The portal never does this; the
	// check is that the servers would not accept it if it did.
	sess := p.sessions.read(cookieRequest(br))
	req, _ := http.NewRequest("POST", "https://"+b.addr+adminCall, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sess.Tokens["a"].Token)
	resB, err := p.proxy.targets["b"].Transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resB.Body.Close()
	if resB.StatusCode != http.StatusUnauthorized && resB.StatusCode != http.StatusForbidden {
		t.Fatalf("B accepted A's token: %s", resB.Status)
	}
}

func cookieRequest(b *browser) *http.Request {
	r, _ := http.NewRequest("GET", publicURL, nil)
	for _, c := range b.cookies {
		r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	return r
}

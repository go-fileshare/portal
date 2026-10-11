// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-fileshare/portal/client"
)

// inProcess is an http.RoundTripper that is the portal itself, with the
// browser's cookies: package client tested against the real handler, not a
// stand-in for it.
type inProcess struct {
	mu sync.Mutex
	b  *browser
}

func (t *inProcess) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	r := req.Clone(req.Context())
	for _, c := range t.b.cookies {
		r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	rec := httptest.NewRecorder()
	t.b.h.ServeHTTP(rec, r)
	res := rec.Result()
	for _, c := range res.Cookies() {
		if c.MaxAge < 0 {
			delete(t.b.cookies, c.Name)
		} else {
			t.b.cookies[c.Name] = c
		}
	}
	return res, nil
}

func clientWorld(t *testing.T) (*world, *fakeDAV, *client.Portal) {
	t.Helper()
	w, dav, b := davWorld(t)
	b.do("POST", "/session/refresh", `{"servers":["a"]}`, true) // only a's tokens, to start with
	return w, dav, client.New(publicURL, &http.Client{Transport: &inProcess{b: b}}, nil)
}

func TestClientSessionAndCalls(t *testing.T) {
	w, dav, p := clientWorld(t)
	ctx := context.Background()
	s, err := p.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if s.Who() != "alice" || len(s.Servers) != 3 || s.Servers[2].ID != "d" || !s.Servers[2].DAV || s.Servers[0].DAV {
		t.Fatalf("%+v", s)
	}
	// d has no token yet: the Doer refreshes and sends the PROPFIND again.
	n := w.idp.refreshN
	req, _ := http.NewRequestWithContext(ctx, "PROPFIND", publicURL+"/dav/d/photos/", strings.NewReader("<propfind/>"))
	req.Header.Set("Depth", "1")
	res, err := p.Doer("d", 64<<10).Do(req)
	if err != nil || res.StatusCode != http.StatusMultiStatus {
		t.Fatalf("%v %v", err, res)
	}
	io.Copy(io.Discard, res.Body)
	if w.idp.refreshN == n || dav.last().method != "PROPFIND" || dav.last().body != len("<propfind/>") {
		t.Fatalf("refreshes %d, last %+v", w.idp.refreshN-n, dav.last())
	}
	// A body over the bound is refused before it leaves.
	big, _ := http.NewRequestWithContext(ctx, "PUT", publicURL+"/dav/d/x", strings.NewReader(strings.Repeat("x", 11)))
	if _, err := p.Doer("d", 10).Do(big); !errors.Is(err, client.ErrTooLarge) {
		t.Fatal(err)
	}
	// EnsureToken before a navigation: a current token for a.
	if err := p.EnsureToken(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(p.LoginURL("/explorer/"), "/login?return=%2Fexplorer%2F") || p.Base() != publicURL {
		t.Fatal(p.LoginURL("/explorer/"))
	}
	end, err := p.Logout(ctx)
	if err != nil || !strings.Contains(end, "/logout") {
		t.Fatalf("%q %v", end, err)
	}
	if _, err := p.Session(ctx); !errors.Is(err, client.ErrNotLoggedIn) {
		t.Fatal(err)
	}
	// A 401 the portal answers without Portal-Refresh is returned as it is:
	// the caller reads it (a server refusing its token answers 401 too, and
	// that is not the session ending).
	req, _ = http.NewRequestWithContext(ctx, "GET", publicURL+"/dav/d/x", nil)
	if res, err := p.Doer("d", 0).Do(req); err != nil || res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after logout: %v %v", err, res)
	}
}

// Twenty calls at once, to a server with no token: one refresh.
func TestClientOneRefreshForConcurrentCalls(t *testing.T) {
	w, _, p := clientWorld(t)
	ctx := context.Background()
	n := w.idp.refreshN
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for range 20 {
		wg.Go(func() {
			req, _ := http.NewRequestWithContext(ctx, "PROPFIND", publicURL+"/dav/d/", nil)
			req.Header.Set("Depth", "0")
			res, err := p.Doer("d", 0).Do(req)
			if err == nil {
				res.Body.Close()
			}
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	// One refresh: d's admin token and its WebDAV token, two purchases.
	if got := w.idp.refreshN - n; got != 2 {
		t.Fatalf("%d token purchases; one refresh of d is 2", got)
	}
}

func TestClientRefreshFailure(t *testing.T) {
	w, _, p := clientWorld(t)
	w.idp.failRefreshFor = davAudience
	req, _ := http.NewRequest("PROPFIND", publicURL+"/dav/d/", nil)
	req.Header.Set("Depth", "0")
	_, err := p.Doer("d", 0).Do(req)
	var re *client.RefreshError
	if !errors.As(err, &re) || !strings.Contains(re.Error(), "502") {
		t.Fatalf("%v", err)
	}
}

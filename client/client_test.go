// SPDX-License-Identifier: BSD-3-Clause

package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The behaviour against the real portal is tested in the portal's own
// package (client_test.go there). These are the edges a real portal is
// awkward to put in: a cap, a fallback, broken answers.

type stub struct {
	srv      *httptest.Server
	refresh  func(servers []string) int
	session  func(w http.ResponseWriter)
	refreshN atomic.Int64
	asked    atomic.Value // []string
}

func newStub(t *testing.T) *stub {
	s := &stub{
		refresh: func([]string) int { return 200 },
		session: func(w http.ResponseWriter) {
			_, _ = w.Write([]byte(`{"subject":"s","servers":[{"id":"a","reachable":true}]}`))
		},
	}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/session":
			s.session(w)
		case "/session/refresh":
			s.refreshN.Add(1)
			var req struct{ Servers []string }
			_ = json.NewDecoder(r.Body).Decode(&req)
			s.asked.Store(req.Servers)
			w.WriteHeader(s.refresh(req.Servers))
		case "/logout":
			w.WriteHeader(http.StatusOK)
		default: // a server call with no token: refresh, then it passes
			if s.refreshN.Load() == 0 {
				w.Header().Set("Portal-Refresh", "x")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func call(p *Portal, server string) error {
	req, _ := http.NewRequest("GET", p.Base()+"/dav/"+server+"/", nil)
	res, err := p.Doer(server, 0).Do(req)
	if err == nil {
		res.Body.Close()
	}
	return err
}

func TestNamesAndDefaults(t *testing.T) {
	if (Server{ID: "a"}).Name() != "a" || (Server{ID: "a", Label: "A"}).Name() != "A" {
		t.Error("Name")
	}
	if (&Session{Subject: "s"}).Who() != "s" || (&Session{Subject: "s", Name: "n"}).Who() != "n" {
		t.Error("Who")
	}
	st := newStub(t)
	p := New(st.srv.URL+"/", nil, nil)
	if p.Base() != st.srv.URL || p.hc != http.DefaultClient {
		t.Error("New")
	}
	s, err := p.Session(context.Background())
	if err != nil || s.Who() != "s" {
		t.Fatal(err)
	}
}

// The servers in use are capped, most recent first.
func TestInUseIsCapped(t *testing.T) {
	p := New("http://x", nil, nil)
	for i := range MaxInUse + 3 {
		p.used(fmt.Sprint("s", i))
	}
	got := p.used("s0")
	if len(got) != MaxInUse || got[0] != "s0" || got[1] != fmt.Sprint("s", MaxInUse+2) {
		t.Fatalf("%v", got)
	}
}

// Past the portal's cookie budget (413), the refresh asks for the one server
// needed.
func TestRefreshFallsBackToOne(t *testing.T) {
	st := newStub(t)
	st.refresh = func(s []string) int {
		if len(s) > 1 {
			return http.StatusRequestEntityTooLarge
		}
		return 200
	}
	p := New(st.srv.URL, nil, nil)
	p.used("b")
	if err := call(p, "a"); err != nil {
		t.Fatal(err)
	}
	if got := st.asked.Load().([]string); len(got) != 1 || got[0] != "a" || st.refreshN.Load() != 2 {
		t.Fatalf("asked %v, %d refreshes", got, st.refreshN.Load())
	}
	// Alone and still too large: said so.
	st.refresh = func([]string) int { return http.StatusRequestEntityTooLarge }
	if err := p.refresh(context.Background(), "a", []string{"a"}); err == nil {
		t.Fatal("a refused refresh went unreported")
	}
}

// A token another tab bought meanwhile is not bought again.
func TestRefreshSkipsACurrentToken(t *testing.T) {
	st := newStub(t)
	exp := time.Now().Add(time.Hour).Format(time.RFC3339)
	st.session = func(w http.ResponseWriter) {
		_, _ = w.Write([]byte(`{"servers":[{"id":"a","token_expires":"` + exp + `"}]}`))
	}
	p := New(st.srv.URL, nil, nil)
	if err := p.EnsureToken(context.Background(), "a"); err != nil || st.refreshN.Load() != 0 {
		t.Fatalf("%v, %d refreshes", err, st.refreshN.Load())
	}
}

func TestBrokenAnswers(t *testing.T) {
	ctx := context.Background()
	st := newStub(t)
	p := New(st.srv.URL, nil, nil)
	st.session = func(w http.ResponseWriter) { w.WriteHeader(http.StatusInternalServerError) }
	if _, err := p.Session(ctx); err == nil || errors.Is(err, ErrNotLoggedIn) {
		t.Errorf("a 500: %v", err)
	}
	st.session = func(w http.ResponseWriter) { _, _ = w.Write([]byte("<html>")) }
	if _, err := p.Session(ctx); err == nil {
		t.Error("not JSON")
	}
	// The session cannot be read during a refresh: the call fails, and says.
	if err := call(p, "a"); err == nil {
		t.Error("a refresh that could not read the session")
	}
	st.session = func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{}`)) }
	st.refresh = func([]string) int { return http.StatusUnauthorized }
	st.refreshN.Store(0) // the stub asks for a refresh until it has seen one
	if err := call(p, "a"); !errors.Is(err, ErrNotLoggedIn) {
		t.Errorf("a 401 refresh: %v", err)
	}
	st.refresh = func([]string) int { return http.StatusBadGateway }
	st.refreshN.Store(0)
	var re *RefreshError
	if err := call(p, "a"); !errors.As(err, &re) || !strings.Contains(re.Error(), "502") {
		t.Errorf("a 502 refresh: %v", err)
	}
	// Nothing listening.
	dead := New("http://127.0.0.1:1", nil, nil)
	if _, err := dead.Session(ctx); err == nil {
		t.Error("Session with nothing listening")
	}
	if _, err := dead.Logout(ctx); err == nil {
		t.Error("Logout with nothing listening")
	}
	if err := dead.postRefresh(ctx, []string{"a"}); err == nil {
		t.Error("refresh with nothing listening")
	}
	if err := call(dead, "a"); err == nil {
		t.Error("a call with nothing listening")
	}
	bad := New("::", nil, nil)
	if _, err := bad.Session(ctx); err == nil {
		t.Error("a malformed base")
	}
	if _, err := bad.Logout(ctx); err == nil {
		t.Error("a malformed base")
	}
	if err := bad.postRefresh(ctx, nil); err == nil {
		t.Error("a malformed base")
	}
}

// A body that cannot be read is an error before anything is sent.
func TestUnreadableBody(t *testing.T) {
	p := New("http://x", nil, nil)
	req, _ := http.NewRequest("PUT", "http://x/dav/a/f", errReader{})
	if _, err := p.Doer("a", 10).Do(req); err == nil {
		t.Fatal("an unreadable body was sent")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("broken") }

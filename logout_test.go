// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/rp"
)

// Logout ends the session for every copy of its cookie, and revokes the
// refresh token at a provider that advertises a revocation endpoint (RFC 7009).
func TestLogoutRevokesTheRefreshTokenAtTheProvider(t *testing.T) {
	w := newWorld(t, func(w *world, _ *strings.Builder) { w.idp.revocation = true })
	b := w.browser()
	b.login(w)
	sess := w.portal.sessions.read(requestWith(b.cookies))
	if sess == nil || sess.Refresh == "" {
		t.Fatal("no session to log out of")
	}
	res := b.do("POST", "/logout", "", true)
	out := readJSON(t, res)
	if out["session_revoked"] != "true" || out["refresh_token"] != "revoked" {
		t.Fatalf("logout answered %v", out)
	}
	w.idp.mu.Lock()
	got := append([]string(nil), w.idp.revokedTokens...)
	w.idp.mu.Unlock()
	if len(got) != 1 || got[0] != sess.Refresh {
		t.Fatalf("the provider was asked to revoke %v, want the session's refresh token", got)
	}
	// The refresh token no longer buys anything.
	if _, err := w.portal.providers[sess.Issuer].buy(t.Context(), sess.Refresh, forResource(w.a.resource)); err == nil {
		t.Error("the revoked refresh token still bought a token")
	}
}

func TestLogoutWithoutARevocationEndpointStillEndsTheSession(t *testing.T) {
	w := newWorld(t)
	b := w.browser()
	b.login(w)
	stolen := maps.Clone(b.cookies)
	out := readJSON(t, b.do("POST", "/logout", "", true))
	if out["session_revoked"] != "true" || out["refresh_token"] != "unsupported" {
		t.Fatalf("logout answered %v", out)
	}
	thief := w.browser()
	thief.cookies = stolen
	if res := thief.do("GET", "/session", "", true); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a copied cookie after logout: %s", res.Status)
	}
	// Another login is another session.
	again := w.browser()
	again.login(w)
	if res := again.do("GET", "/session", "", true); res.StatusCode != http.StatusOK {
		t.Fatalf("a new login after a logout: %s", res.Status)
	}
}

// A logout lasts as long as the sessions do: across a restart, with the file.
func TestLogoutSurvivesARestartWithTheRevocationsFile(t *testing.T) {
	w := newWorld(t)
	w.cfg.Session.RevocationsFile = filepath.Join(w.dir, "state", "revoked")
	boot := func() {
		p, err := newPortal(t.Context(), w.cfg, http.DefaultClient)
		if err != nil {
			t.Fatal(err)
		}
		p.logf = t.Logf
		w.portal, w.h = p, p.handler()
	}
	boot()
	b := w.browser()
	b.login(w)
	stolen := maps.Clone(b.cookies)
	b.do("POST", "/logout", "", true)
	boot() // the portal restarts: the sessions are sealed, so they would open again
	thief := w.browser()
	thief.cookies = stolen
	if res := thief.do("GET", "/session", "", true); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a cookie copied before a logout, after a restart: %s", res.Status)
	}
}

func forResource(r string) rp.For { return rp.For{Resource: r} }

func httpRecorder() *httptest.ResponseRecorder { return httptest.NewRecorder() }

func requestWith(cookies map[string]*http.Cookie) *http.Request {
	r, _ := http.NewRequest("GET", "/", nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	return r
}

// The revocation set on its own: persisted, shared, bounded, self-cleaning.
func TestRevocationsFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "sub", "revoked")
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	r, err := newRevocations(file, clock)
	if err != nil {
		t.Fatal(err)
	}
	a, b := newSessionID(), newSessionID()
	if r.revoked(a) {
		t.Fatal("a fresh id is revoked")
	}
	if err := r.revoke(a, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := r.revoke(b, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if !r.revoked(a) || !r.revoked(b) {
		t.Fatal("a revoked id is not revoked")
	}
	st, err := os.Stat(file)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("revocations file: %v %v", st, err)
	}
	// A restart: another set over the same file.
	r2, err := newRevocations(file, clock)
	if err != nil || !r2.revoked(a) || !r2.revoked(b) {
		t.Fatalf("after a restart: %v", err)
	}
	// Another copy of the portal appends: this one sees it within a second.
	c := newSessionID()
	if err := r2.revoke(c, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if r.revoked(c) {
		t.Fatal("seen at once: the poll should wait a second")
	}
	now = now.Add(2 * time.Second)
	if !r.revoked(c) {
		t.Fatal("a revocation made by another copy was not seen")
	}
	// An entry is dropped after its session's end, and a file with expired
	// lines is compacted at load.
	now = now.Add(2 * time.Minute)
	if r.revoked(b) {
		t.Fatal("an entry stayed revoked after its session ended")
	}
	r3, err := newRevocations(file, clock)
	if err != nil || r3.revoked(b) || !r3.revoked(a) {
		t.Fatalf("after compaction: %v", err)
	}
	data, _ := os.ReadFile(file)
	if strings.Contains(string(data), b) {
		t.Error("the expired entry is still in the file")
	}
	// Garbage lines are skipped, not fatal.
	if err := os.WriteFile(file, []byte("garbage\n"+a+" not-a-time\n"+a+" "+now.Add(time.Hour).Format(time.RFC3339)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r4, err := newRevocations(file, clock)
	if err != nil || !r4.revoked(a) {
		t.Fatalf("a file with garbage: %v", err)
	}
}

func TestRevocationsAreBounded(t *testing.T) {
	now := time.Now()
	r, _ := newRevocations("", func() time.Time { return now })
	for i := 0; i < maxRevocations; i++ {
		r.ids[sessionIDOf(i)] = now.Add(time.Hour)
	}
	if err := r.revoke(newSessionID(), now.Add(time.Hour)); err == nil {
		t.Fatal("a logout was recorded past the bound")
	}
	if err := r.revoke(sessionIDOf(1), now.Add(time.Hour)); err != nil {
		t.Fatalf("revoking an id already there: %v", err)
	}
	// A file past the bound is refused at load.
	dir := t.TempDir()
	file := filepath.Join(dir, "revoked")
	var b strings.Builder
	line := sessionIDOf(7) + " " + now.Add(time.Hour).UTC().Format(time.RFC3339) + "\n"
	for i := 0; i <= maxRevocations; i++ {
		b.WriteString(strings.Replace(line, sessionIDOf(7), sessionIDOf(i), 1))
	}
	if err := os.WriteFile(file, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newRevocations(file, func() time.Time { return now }); err == nil {
		t.Fatal("a file past the bound was loaded")
	}
}

func sessionIDOf(i int) string {
	b := []byte(strings.Repeat("A", 22))
	for k := 0; k < 8 && i > 0; k++ {
		b[k] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[i%64]
		i /= 64
	}
	return string(b)
}

func TestRevocationsFileErrors(t *testing.T) {
	dir := t.TempDir()
	// A file that cannot be a directory's child.
	if err := os.WriteFile(filepath.Join(dir, "f"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newRevocations(filepath.Join(dir, "f", "x"), time.Now); err == nil {
		t.Error("a revocations file under a regular file")
	}
	// A directory where the file should be: the load fails.
	if _, err := newRevocations(dir, time.Now); err == nil {
		t.Error("a directory as the revocations file")
	}
}

func TestSessionsWithoutAnIDAreRefused(t *testing.T) {
	w := newWorld(t)
	rec := httpRecorder()
	if err := w.portal.sessions.write(rec, requestWith(nil), &session{Issuer: "i", Subject: "s", Expires: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	r, _ := http.NewRequest("GET", "/", nil)
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}
	if w.portal.sessions.read(r) != nil {
		t.Fatal("a session with no id (from before logouts ended sessions) was accepted")
	}
}

// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A provider whose answers are wrong in one way each: the portal refuses
// rather than guesses.
func TestTokenEndpointAnswers(t *testing.T) {
	var answer func(w http.ResponseWriter)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { answer(w) }))
	defer srv.Close()
	p := &provider{cfg: &issuerBlock{ClientID: "c", secret: "s"}, tokenURL: srv.URL, client: http.DefaultClient}
	cases := map[string]struct {
		answer func(w http.ResponseWriter)
		grant  bool // an invalid_grant, which ends a session
	}{
		"invalid_grant":            {func(w http.ResponseWriter) { tokenErr(w, "invalid_grant") }, true},
		"a 500 with no error code": {func(w http.ResponseWriter) { http.Error(w, "x", 500) }, false},
		"not JSON":                 {func(w http.ResponseWriter) { _, _ = w.Write([]byte("<html>")) }, false},
		"no access token": {func(w http.ResponseWriter) {
			_ = json.NewEncoder(w).Encode(map[string]string{"token_type": "Bearer"})
		}, false},
		"not a bearer token": {func(w http.ResponseWriter) {
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "x", "token_type": "DPoP"})
		}, false},
	}
	for name, c := range cases {
		answer = c.answer
		_, err := p.refresh(context.Background(), "rt", &serverBlock{Resource: "https://a", Scope: "x"})
		var te *tokenError
		if err == nil || (errors.As(err, &te) && te.Code == "invalid_grant") != c.grant {
			t.Errorf("%s: %v", name, err)
		}
	}
	p.tokenURL = "http://127.0.0.1:1"
	if _, err := p.exchange(context.Background(), "c", "v"); err == nil {
		t.Error("an unreachable token endpoint answered")
	}
	p.tokenURL = "::"
	if _, err := p.exchange(context.Background(), "c", "v"); err == nil {
		t.Error("a malformed token URL answered")
	}
}

func TestDiscoveryAnswers(t *testing.T) {
	var doc any
	status := 200
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		if s, ok := doc.(string); ok {
			_, _ = w.Write([]byte(s))
			return
		}
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer srv.Close()
	is := &issuerBlock{URL: srv.URL, ClientID: "c"}
	good := func() map[string]any {
		return map[string]any{"issuer": srv.URL, "authorization_endpoint": srv.URL + "/a", "token_endpoint": srv.URL + "/t",
			"jwks_uri": srv.URL + "/k"}
	}
	for name, set := range map[string]func(){
		"a 404":                         func() { status = 404 },
		"not JSON":                      func() { doc = "<html>" },
		"a token endpoint in the clear": func() { d := good(); d["token_endpoint"] = "http://idp.example/t"; doc = d },
		"keys that do not load":         func() { d := good(); doc = d }, // the JWKS URL answers the document, not keys
	} {
		status, doc = 200, nil
		set()
		if _, err := newProvider(context.Background(), is, publicURL+"/callback", http.DefaultClient); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := newProvider(context.Background(), &issuerBlock{URL: "http://127.0.0.1:1"}, "", http.DefaultClient); err == nil {
		t.Error("an unreachable provider was accepted")
	}
	if _, err := newProvider(context.Background(), &issuerBlock{URL: "::"}, "", http.DefaultClient); err == nil {
		t.Error("a malformed issuer was accepted")
	}
}

// An end_session_endpoint in the clear is dropped, not followed.
func TestEndSessionInTheClearIsDropped(t *testing.T) {
	idp := newTestIdP(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": idp.issuer, "authorization_endpoint": idp.issuer + "/authorize?a=1",
			"token_endpoint": idp.issuer + "/token", "jwks_uri": idp.issuer + "/jwks", "end_session_endpoint": "http://idp.example/logout"})
	}))
	defer srv.Close()
	// The document is served from srv, for the issuer idp: point the
	// issuer at idp, and discovery at srv by a client that rewrites.
	c := &http.Client{Transport: rewrite{to: srv.URL}}
	p, err := newProvider(context.Background(), &issuerBlock{URL: idp.issuer, ClientID: "portal", Scopes: []string{"openid"}}, publicURL+"/callback", c)
	if err != nil {
		t.Fatal(err)
	}
	if p.endURL != "" {
		t.Fatalf("kept %q", p.endURL)
	}
	if _, to := p.start(time.Now(), "/"); !containsAll(to, "/authorize?a=1&", "code_challenge_method=S256") {
		t.Fatalf("authorization URL %q", to)
	}
}

type rewrite struct{ to string }

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Path == "/.well-known/openid-configuration" {
		u := *req.URL
		u.Host = r.to[len("http://"):]
		req = req.Clone(req.Context())
		req.URL = &u
	}
	return http.DefaultTransport.RoundTrip(req)
}

func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !strings.Contains(s, p) {
			return false
		}
	}
	return true
}

func TestProxyCAFile(t *testing.T) {
	dir := t.TempDir()
	cert, _ := selfSigned(t, dir)
	if _, err := newProxy([]serverBlock{{ID: "a", URL: "https://a", CAFile: cert}}); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty.pem")
	_ = os.WriteFile(empty, []byte("nothing"), 0o644)
	for _, s := range []serverBlock{
		{ID: "a", URL: "https://a", CAFile: filepath.Join(dir, "none.pem")},
		{ID: "a", URL: "https://a", CAFile: empty},
		{ID: "a", URL: "%zz"},
	} {
		if _, err := newProxy([]serverBlock{s}); err == nil {
			t.Errorf("%+v accepted", s)
		}
	}
}

// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// testIdP is an OpenID provider small enough to read, strict where the
// portal must be strict with a real one: exact redirect URI, PKCE S256 only,
// client_secret_basic, refresh tokens that ROTATE with reuse detection (a
// retired token revokes its family, RFC 9700 §4.14.2), and RFC 8707 resource
// indicators that become the access token's only audience.
type testIdP struct {
	t      *testing.T
	srv    *httptest.Server
	key    *ecdsa.PrivateKey
	issuer string

	clientID, secret, redirect string
	resources                  []string // what a resource indicator may name

	mu       sync.Mutex
	codes    map[string]codeGrant
	live     map[string]string // refresh token -> family
	retired  map[string]string // refresh token -> family
	revoked  map[string]bool   // family
	refreshN int

	// knobs for the failure cases
	badNonce, noRefresh, noRotate, noS256, wrongIssuer bool
	failRefreshFor                                     string // a resource whose refresh answers 500
	extraAud                                           bool   // ID token with two audiences and no azp
}

type codeGrant struct {
	challenge, nonce, redirect string
}

func newTestIdP(t *testing.T) *testIdP {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &testIdP{t: t, key: k, clientID: "portal", secret: "s3cret",
		codes: map[string]codeGrant{}, live: map[string]string{}, retired: map[string]string{}, revoked: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /jwks", p.jwks)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	p.issuer = p.srv.URL
	return p
}

func (p *testIdP) discovery(w http.ResponseWriter, r *http.Request) {
	iss := p.issuer
	if p.wrongIssuer {
		iss = p.issuer + "/other"
	}
	d := map[string]any{"issuer": iss, "authorization_endpoint": p.issuer + "/authorize",
		"token_endpoint": p.issuer + "/token", "jwks_uri": p.issuer + "/jwks",
		"end_session_endpoint": p.issuer + "/logout?x=1"}
	if p.noS256 {
		d["code_challenge_methods_supported"] = []string{"plain"}
	} else {
		d["code_challenge_methods_supported"] = []string{"S256"}
	}
	_ = json.NewEncoder(w).Encode(d)
}

func (p *testIdP) jwks(w http.ResponseWriter, r *http.Request) {
	pub := p.key.PublicKey
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
		"kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256", "use": "sig",
		"x": b64(pub.X.FillBytes(make([]byte, 32))), "y": b64(pub.Y.FillBytes(make([]byte, 32))),
	}}})
}

func (p *testIdP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != p.clientID || q.Get("redirect_uri") != p.redirect ||
		q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		http.Error(w, "bad authorization request", http.StatusBadRequest)
		return
	}
	code := random()
	p.mu.Lock()
	p.codes[code] = codeGrant{challenge: q.Get("code_challenge"), nonce: q.Get("nonce"), redirect: q.Get("redirect_uri")}
	p.mu.Unlock()
	v := url.Values{"code": {code}, "state": {q.Get("state")}, "iss": {p.issuer}}
	http.Redirect(w, r, p.redirect+"?"+v.Encode(), http.StatusFound)
}

func (p *testIdP) token(w http.ResponseWriter, r *http.Request) {
	id, secret, ok := r.BasicAuth()
	if !ok {
		tokenErr(w, "invalid_client")
		return
	}
	id, _ = url.QueryUnescape(id)
	secret, _ = url.QueryUnescape(secret)
	if id != p.clientID || secret != p.secret {
		tokenErr(w, "invalid_client")
		return
	}
	_ = r.ParseForm()
	p.mu.Lock()
	defer p.mu.Unlock()
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		g, ok := p.codes[r.PostForm.Get("code")]
		delete(p.codes, r.PostForm.Get("code"))
		if !ok || g.redirect != r.PostForm.Get("redirect_uri") || challenge(r.PostForm.Get("code_verifier")) != g.challenge {
			tokenErr(w, "invalid_grant")
			return
		}
		nonce := g.nonce
		if p.badNonce {
			nonce = "not-" + nonce
		}
		idc := map[string]any{"iss": p.issuer, "sub": "alice-sub", "aud": p.clientID, "nonce": nonce,
			"preferred_username": "alice", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}
		if p.extraAud {
			idc["aud"] = []string{p.clientID, "someone-else"}
		}
		resp := map[string]any{"access_token": p.sign("at+jwt", p.at(p.clientID)), "token_type": "Bearer",
			"expires_in": 300, "id_token": p.sign("JWT", idc)}
		if !p.noRefresh {
			resp["refresh_token"] = p.newRefresh(random())
		}
		_ = json.NewEncoder(w).Encode(resp)
	case "refresh_token":
		rt := r.PostForm.Get("refresh_token")
		fam, ok := p.live[rt]
		if !ok || p.revoked[fam] {
			if f, again := p.retired[rt]; again {
				p.revoked[f] = true // a retired token came back: the family ends
			}
			tokenErr(w, "invalid_grant")
			return
		}
		res := r.PostForm.Get("resource")
		if res == "" || !slices.Contains(p.resources, res) {
			tokenErr(w, "invalid_target")
			return
		}
		if res == p.failRefreshFor {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		p.refreshN++
		resp := map[string]any{"access_token": p.sign("at+jwt", p.at(res)), "token_type": "bearer", "expires_in": 300}
		if !p.noRotate {
			delete(p.live, rt)
			p.retired[rt] = fam
			resp["refresh_token"] = p.newRefresh(fam)
		}
		_ = json.NewEncoder(w).Encode(resp)
	default:
		tokenErr(w, "unsupported_grant_type")
	}
}

func (p *testIdP) newRefresh(family string) string {
	rt := random()
	p.live[rt] = family
	return rt
}

func (p *testIdP) at(aud string) map[string]any {
	return map[string]any{"iss": p.issuer, "sub": "alice-sub", "aud": aud, "client_id": p.clientID,
		"preferred_username": "alice", "groups": []string{"fileshare-admins"},
		"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(), "jti": random()}
}

func (p *testIdP) sign(typ string, claims map[string]any) string {
	h, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": "k1", "typ": typ})
	c, _ := json.Marshal(claims)
	in := b64(h) + "." + b64(c)
	sum := sha256.Sum256([]byte(in))
	r, s, err := ecdsa.Sign(rand.Reader, p.key, sum[:])
	if err != nil {
		p.t.Fatal(err)
	}
	sig := append(pad32(r), pad32(s)...)
	return in + "." + b64(sig)
}

func pad32(n *big.Int) []byte { return n.FillBytes(make([]byte, 32)) }

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func tokenErr(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": "test"})
}

// audOf reads a JWT's aud without verifying it: what the IdP addressed.
func audOf(t *testing.T, jwt string) any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	_ = json.Unmarshal(b, &c)
	return c["aud"]
}

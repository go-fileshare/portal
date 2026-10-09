// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// A session is everything the portal knows about one login. It lives in the
// browser, sealed (seal.go), so that every copy of the portal can serve every
// request: there is no store to share and nothing to replicate.
//
// The tokens are in it. They never reach the page -- the cookie is HttpOnly
// and sealed -- and the page never needs them: it calls the portal, which
// adds the token of the server the call is for (proxy.go).
type session struct {
	Issuer  string    `json:"iss"`
	Subject string    `json:"sub"`
	Name    string    `json:"name,omitempty"`
	Expires time.Time `json:"exp"` // the login's end, fixed at the login
	// Refresh is the refresh token. Every access token below was bought
	// with it; a provider that rotates it hands a new one each time.
	Refresh string `json:"rt,omitempty"`
	// Tokens holds an access token per server id, addressed to that server
	// alone.
	Tokens map[string]accessToken `json:"at,omitempty"`
}

type accessToken struct {
	Token   string    `json:"t"`
	Expires time.Time `json:"e"`
}

// A flow is the login in progress, between the redirect to the provider and
// its return: what the callback must find again to accept the code.
type flow struct {
	Issuer   string    `json:"iss"`
	State    string    `json:"state"`
	Nonce    string    `json:"nonce"`
	Verifier string    `json:"pkce"`
	Return   string    `json:"ret"` // where to go once logged in: a path on the portal
	Expires  time.Time `json:"exp"`
}

// Cookie names. __Host-: Secure, Path=/ and no Domain, or the browser refuses
// to store it, so no sibling host can set or read it; -Http-: set over HTTP
// only, never by script (draft-ietf-httpbis-layered-cookies; a browser that
// does not know that prefix still enforces __Host-).
// draft-ietf-oauth-browser-based-apps-27 §6.1.3.2.
const (
	sessionCookie = "__Host-Http-portal"
	flowCookie    = "__Host-Http-portal-flow"
	flowLifetime  = 10 * time.Minute
)

// A browser need keep no more than 4096 bytes of one cookie, name and value
// included (RFC 6265 §6.1), and at least 50 per domain. A session holding
// tokens for several servers outgrows one cookie, so it is split over
// numbered ones -- __Host-Http-portal.0, .1 ... -- each kept well inside the
// limit, and no more than the session block's max_cookie_bytes (at most
// maxChunks of them): past that, the request is refused rather than
// half-stored.
const (
	chunkSize = 3800
	maxChunks = 12
)

var errTooLarge = errors.New("the session would not fit in the cookies a browser keeps")

// sessions reads and writes the session and flow cookies.
type sessions struct {
	sealer *sealer
	now    func() time.Time
	limit  int // bytes of sealed session, all chunks together
}

// read returns the session the request carries, or nil when it carries none
// that opens and has not expired.
func (ss *sessions) read(r *http.Request) *session {
	var b strings.Builder
	for i := 0; i < maxChunks; i++ {
		c, err := r.Cookie(chunkName(i))
		if err != nil {
			break
		}
		b.WriteString(c.Value)
	}
	if b.Len() == 0 {
		return nil
	}
	plain, err := ss.sealer.open(sessionCookie, b.String())
	if err != nil {
		return nil
	}
	var s session
	if json.Unmarshal(plain, &s) != nil || !ss.now().Before(s.Expires) {
		return nil
	}
	return &s
}

// write seals s into the response, and clears the chunks a larger session
// left behind -- a stale chunk appended to a shorter value would not open.
func (ss *sessions) write(w http.ResponseWriter, r *http.Request, s *session) error {
	plain, err := json.Marshal(s)
	if err != nil {
		return err
	}
	sealed := ss.sealer.seal(sessionCookie, plain)
	n := (len(sealed) + chunkSize - 1) / chunkSize
	if len(sealed) > ss.limit {
		return fmt.Errorf("%w: %d bytes", errTooLarge, len(sealed))
	}
	maxAge := int(s.Expires.Sub(ss.now()).Seconds())
	for i := 0; i < n; i++ {
		end := min((i+1)*chunkSize, len(sealed))
		http.SetCookie(w, strictCookie(chunkName(i), sealed[i*chunkSize:end], maxAge))
	}
	for i := n; i < maxChunks; i++ {
		if _, err := r.Cookie(chunkName(i)); err == nil {
			http.SetCookie(w, strictCookie(chunkName(i), "", -1))
		}
	}
	return nil
}

// clear ends the session in this browser.
func (ss *sessions) clear(w http.ResponseWriter, r *http.Request) {
	for i := 0; i < maxChunks; i++ {
		if _, err := r.Cookie(chunkName(i)); err == nil {
			http.SetCookie(w, strictCookie(chunkName(i), "", -1))
		}
	}
}

func chunkName(i int) string { return sessionCookie + "." + strconv.Itoa(i) }

// strictCookie is a session cookie: SameSite=Strict, so a request another
// site makes the browser send carries no session at all (BBA-27 §6.1.3.3.1).
func strictCookie(name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: maxAge,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
}

// writeFlow stores the login in progress. Lax, not Strict: the callback is a
// top-level navigation FROM the provider's site, which a Strict cookie would
// not accompany. It carries no session, only what proves the callback answers
// a login this browser started.
func (ss *sessions) writeFlow(w http.ResponseWriter, f *flow) error {
	plain, err := json.Marshal(f)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: flowCookie, Value: ss.sealer.seal(flowCookie, plain),
		Path: "/", MaxAge: int(flowLifetime.Seconds()), Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode})
	return nil
}

// takeFlow reads the login in progress and clears it: a flow is used once.
func (ss *sessions) takeFlow(w http.ResponseWriter, r *http.Request) *flow {
	c, err := r.Cookie(flowCookie)
	if err != nil {
		return nil
	}
	http.SetCookie(w, &http.Cookie{Name: flowCookie, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	plain, err := ss.sealer.open(flowCookie, c.Value)
	if err != nil {
		return nil
	}
	var f flow
	if json.Unmarshal(plain, &f) != nil || !ss.now().Before(f.Expires) {
		return nil
	}
	return &f
}

// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// A portal is the server behind the UIs.
//
//	GET  /login?issuer=…&return=…   start a login (the issuer may be left out when there is one)
//	GET  /callback                  the provider's answer
//	GET  /session                   who is logged in, and which servers this session reaches
//	POST /session/refresh           buy a token for each server asked for
//	POST /logout                    end the session here, and say where to end it at the provider
//	POST /api/<server>/<rpc>        a Connect call, passed to that server with its token (proxy.go)
//	GET  /console/, /explorer/      the UIs (static.go)
//
// Everything but /login, /callback and the UIs' files is called by the UI
// with fetch, and must carry the static header Portal-Request: 1 -- the CSRF
// defence of BBA-27 §6.1.3.3.2: a page on another origin cannot add it
// without a preflight, and the portal answers no preflight.
type portal struct {
	cfg       *config
	providers map[string]*provider // by issuer URL
	servers   map[string]*serverBlock
	sessions  *sessions
	proxy     *proxy
	now       func() time.Time
	logf      func(format string, args ...any)
}

const requestHeader = "Portal-Request"

func newPortal(ctx context.Context, cfg *config, client *http.Client) (*portal, error) {
	s, err := newSealer(cfg.Session.keys)
	if err != nil {
		return nil, err
	}
	p := &portal{cfg: cfg, providers: map[string]*provider{}, servers: map[string]*serverBlock{},
		now: time.Now, logf: log.Printf}
	p.sessions = &sessions{sealer: s, now: func() time.Time { return p.now() }, limit: cfg.Session.MaxCookieBytes}
	redirect := strings.TrimSuffix(cfg.public.String(), "/") + "/callback"
	for i := range cfg.Issuers {
		is := &cfg.Issuers[i]
		pv, err := newProvider(ctx, is, redirect, client)
		if err != nil {
			return nil, fmt.Errorf("issuer %s: %w", is.URL, err)
		}
		p.providers[is.URL] = pv
	}
	for i := range cfg.Servers {
		p.servers[cfg.Servers[i].ID] = &cfg.Servers[i]
	}
	p.proxy, err = newProxy(cfg.Servers)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (p *portal) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", p.login)
	mux.HandleFunc("GET /callback", p.callback)
	mux.Handle("GET /session", p.fetchOnly(p.whoami))
	mux.Handle("POST /session/refresh", p.fetchOnly(p.refresh))
	mux.Handle("POST /logout", p.fetchOnly(p.logout))
	mux.Handle("POST /api/{server}/{rpc...}", p.fetchOnly(p.api))
	mux.Handle("/", newStatic(p.cfg.UIs))
	return securityHeaders(mux)
}

// fetchOnly lets through what the portal's own pages sent: the static header,
// and -- when the browser says -- the same origin. Anything else is refused
// before it is read.
func (p *portal) fetchOnly(h http.HandlerFunc) http.Handler {
	origin := strings.TrimSuffix(p.cfg.public.String(), "/")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(requestHeader) != "1" {
			jsonError(w, http.StatusForbidden, "permission_denied", "a request the portal's pages did not send")
			return
		}
		if o := r.Header.Get("Origin"); o != "" && o != origin {
			jsonError(w, http.StatusForbidden, "permission_denied", "a request from another origin")
			return
		}
		if s := r.Header.Get("Sec-Fetch-Site"); s != "" && s != "same-origin" {
			jsonError(w, http.StatusForbidden, "permission_denied", "a request from another site")
			return
		}
		h(w, r)
	})
}

func (p *portal) login(w http.ResponseWriter, r *http.Request) {
	ret := safeReturn(r.URL.Query().Get("return"))
	iss := r.URL.Query().Get("issuer")
	if iss == "" && len(p.cfg.Issuers) == 1 {
		iss = p.cfg.Issuers[0].URL
	}
	pv := p.providers[iss]
	if pv == nil {
		p.chooseIssuer(w, ret)
		return
	}
	f, to := pv.start(p.now(), ret)
	if err := p.sessions.writeFlow(w, f); err != nil {
		http.Error(w, "the login could not start", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, to, http.StatusFound)
}

var chooser = template.Must(template.New("").Parse(`<!doctype html>
<meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Log in</title>
<style>body{font:16px system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem}a{display:block;padding:.75rem 0}</style>
<h1>Log in with</h1>
{{range .}}<a href="{{.Href}}">{{.Name}}</a>
{{end}}`))

// chooseIssuer lists the providers when there are several and none was
// named. Each link is to /login with that issuer.
func (p *portal) chooseIssuer(w http.ResponseWriter, ret string) {
	type choice struct{ Name, Href string }
	var cs []choice
	for _, is := range p.cfg.Issuers {
		q := url.Values{"issuer": {is.URL}, "return": {ret}}
		cs = append(cs, choice{Name: is.URL, Href: "/login?" + q.Encode()})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = chooser.Execute(w, cs)
}

// safeReturn keeps a return address on the portal: a path, never a URL
// that leaves it. "//evil.example" is a path to a browser's eye only
// until it is followed, and "/\evil.example" is the same thing to some.
func safeReturn(ret string) string {
	if !strings.HasPrefix(ret, "/") || strings.HasPrefix(ret, "//") || strings.HasPrefix(ret, "/\\") ||
		strings.ContainsAny(ret, "\r\n\t") {
		return "/"
	}
	if u, err := url.Parse(ret); err != nil || u.Scheme != "" || u.Host != "" {
		return "/"
	}
	return ret
}

func (p *portal) callback(w http.ResponseWriter, r *http.Request) {
	f := p.sessions.takeFlow(w, r)
	q := r.URL.Query()
	if f == nil {
		loginFailed(w, "This login was not started here, or took longer than 10 minutes.")
		return
	}
	// RFC 6749 §10.12: state ties the answer to the browser that asked.
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(f.State)) != 1 {
		loginFailed(w, "The answer does not belong to this login.")
		return
	}
	// RFC 9207: an answer that names its issuer must name the one asked.
	if iss := q.Get("iss"); iss != "" && iss != f.Issuer {
		loginFailed(w, "The answer came from another provider.")
		return
	}
	if e := q.Get("error"); e != "" {
		p.logf("login: the provider said %s: %s", e, q.Get("error_description"))
		loginFailed(w, "The provider did not log you in.")
		return
	}
	pv := p.providers[f.Issuer]
	if pv == nil {
		loginFailed(w, "This provider is no longer configured.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	tr, err := pv.exchange(ctx, q.Get("code"), f.Verifier)
	if err != nil {
		p.logf("login: code exchange at %s: %v", f.Issuer, err)
		loginFailed(w, "The provider did not accept the login.")
		return
	}
	id, err := pv.verifyID(ctx, tr.IDToken, f.Nonce)
	if err != nil {
		p.logf("login: ID token from %s: %v", f.Issuer, err)
		loginFailed(w, "The provider's answer could not be verified.")
		return
	}
	if tr.RefreshToken == "" {
		// The portal buys each server its own token with the refresh token;
		// without one it could reach none of them.
		p.logf("login: %s issued no refresh token to %s; allow refresh tokens (offline_access) for this client", f.Issuer, pv.cfg.ClientID)
		loginFailed(w, "The provider is not configured to let the portal act for you.")
		return
	}
	s := &session{Issuer: f.Issuer, Subject: id.Subject(), Name: id.Username(),
		Expires: p.now().Add(p.cfg.Session.lifetime), Refresh: tr.RefreshToken}
	if err := p.sessions.write(w, r, s); err != nil {
		loginFailed(w, "The session could not be stored.")
		return
	}
	p.logf("login: %s %s", s.Issuer, s.Subject)
	// A page, not a redirect: the navigation to the UI then starts on this
	// site, and the SameSite=Strict session cookie goes with it. A redirect
	// would continue the provider's cross-site navigation, without it.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = loggedIn.Execute(w, f.Return)
}

var loggedIn = template.Must(template.New("").Parse(`<!doctype html>
<meta charset="utf-8"><meta http-equiv="refresh" content="0;url={{.}}">
<title>Logged in</title><p><a href="{{.}}">Continue</a>`))

func loginFailed(w http.ResponseWriter, why string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusUnauthorized)
	_ = failedPage.Execute(w, why)
}

var failedPage = template.Must(template.New("").Parse(`<!doctype html>
<meta charset="utf-8"><title>Not logged in</title>
<p>{{.}}</p><p><a href="/login">Log in again</a>`))

// serverView is what the UI is told about a server.
type serverView struct {
	ID        string     `json:"id"`
	Label     string     `json:"label,omitempty"`
	Reachable bool       `json:"reachable"` // its issuer is this session's
	Token     *time.Time `json:"token_expires,omitempty"`
}

type sessionView struct {
	Issuer  string       `json:"issuer"`
	Subject string       `json:"subject"`
	Name    string       `json:"name,omitempty"`
	Expires time.Time    `json:"expires"`
	Servers []serverView `json:"servers"`
}

func (p *portal) view(s *session) sessionView {
	v := sessionView{Issuer: s.Issuer, Subject: s.Subject, Name: s.Name, Expires: s.Expires, Servers: []serverView{}}
	for _, sb := range p.cfg.Servers {
		sv := serverView{ID: sb.ID, Label: sb.Label, Reachable: sb.Issuer == s.Issuer}
		if t, ok := s.Tokens[sb.ID]; ok {
			e := t.Expires
			sv.Token = &e
		}
		v.Servers = append(v.Servers, sv)
	}
	return v
}

func (p *portal) whoami(w http.ResponseWriter, r *http.Request) {
	s := p.sessions.read(r)
	if s == nil {
		jsonError(w, http.StatusUnauthorized, "unauthenticated", "not logged in")
		return
	}
	writeJSON(w, http.StatusOK, p.view(s))
}

// refresh buys an access token for each server the UI names, and keeps
// those alone: a session holds tokens for the servers in use, which keeps
// its cookies small however many servers the portal knows.
//
// It is the ONLY place the refresh token is spent. A provider that rotates
// refresh tokens (RFC 9700 §4.14.2) revokes the whole grant when a retired
// one comes back -- which two requests refreshing at once would do. So the
// proxy never refreshes; it answers "unauthenticated" and the UI calls this,
// one call at a time across its tabs (the Web Locks API), and the servers
// are refreshed one after the other within it, each with the refresh token
// the previous answer returned.
func (p *portal) refresh(w http.ResponseWriter, r *http.Request) {
	s := p.sessions.read(r)
	if s == nil {
		jsonError(w, http.StatusUnauthorized, "unauthenticated", "not logged in")
		return
	}
	var req struct {
		Servers []string `json:"servers"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil || len(req.Servers) == 0 {
		jsonError(w, http.StatusBadRequest, "invalid_argument", `the body is {"servers": ["<id>", ...]}`)
		return
	}
	pv := p.providers[s.Issuer]
	if pv == nil {
		p.sessions.clear(w, r)
		jsonError(w, http.StatusUnauthorized, "unauthenticated", "this provider is no longer configured")
		return
	}
	var want []*serverBlock
	for _, id := range req.Servers {
		sb := p.servers[id]
		if sb == nil || sb.Issuer != s.Issuer {
			jsonError(w, http.StatusBadRequest, "invalid_argument", fmt.Sprintf("server %q is not reachable from this session", id))
			return
		}
		if !slices.Contains(want, sb) {
			want = append(want, sb)
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	now := p.now()
	tokens := map[string]accessToken{}
	for _, sb := range want {
		tr, err := pv.refresh(ctx, s.Refresh, sb)
		if err != nil {
			var te *tokenError
			if errors.As(err, &te) && te.Code == "invalid_grant" {
				// The grant is over -- expired, revoked, or a rotated
				// token replayed somewhere. Only a new login helps.
				p.logf("refresh: %s %s: %v", s.Issuer, s.Subject, err)
				p.sessions.clear(w, r)
				jsonError(w, http.StatusUnauthorized, "unauthenticated", "the login has ended")
				return
			}
			// Store what was bought so far: a rotated refresh token that
			// is not kept is a session lost at the next call.
			p.logf("refresh: %s for %s: %v", sb.ID, s.Subject, err)
			s.Tokens = tokens
			_ = p.sessions.write(w, r, s)
			jsonError(w, http.StatusBadGateway, "unavailable", fmt.Sprintf("no token for server %q: the provider did not answer", sb.ID))
			return
		}
		if tr.RefreshToken != "" {
			s.Refresh = tr.RefreshToken
		}
		exp := now.Add(time.Duration(tr.ExpiresIn) * time.Second)
		if tr.ExpiresIn <= 0 {
			exp = now.Add(5 * time.Minute)
		}
		tokens[sb.ID] = accessToken{Token: tr.AccessToken, Expires: exp}
	}
	s.Tokens = tokens
	if err := p.sessions.write(w, r, s); err != nil {
		// Too many servers at once for the cookies: keep the refresh token,
		// which was perhaps rotated, and drop the tokens.
		s.Tokens = nil
		_ = p.sessions.write(w, r, s)
		jsonError(w, http.StatusRequestEntityTooLarge, "resource_exhausted", "too many servers at once: ask for fewer")
		return
	}
	writeJSON(w, http.StatusOK, p.view(s))
}

func (p *portal) logout(w http.ResponseWriter, r *http.Request) {
	s := p.sessions.read(r)
	p.sessions.clear(w, r)
	out := map[string]string{}
	if s != nil {
		p.logf("logout: %s %s", s.Issuer, s.Subject)
		if pv := p.providers[s.Issuer]; pv != nil && pv.endURL != "" {
			// OIDC RP-Initiated Logout 1.0 §2: client_id identifies the
			// client when there is no id_token_hint to.
			q := url.Values{"client_id": {pv.cfg.ClientID},
				"post_logout_redirect_uri": {strings.TrimSuffix(p.cfg.public.String(), "/") + "/"}}
			sep := "?"
			if strings.Contains(pv.endURL, "?") {
				sep = "&"
			}
			out["end_session"] = pv.endURL + sep + q.Encode()
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// jsonError is a Connect error body (connectrpc.com/docs/protocol, "Error
// end-stream"), so that the UI's Connect client reads the portal's own
// refusals as it reads a server's.
func jsonError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"code": code, "message": msg})
}

// securityHeaders apply to everything the portal sends.
func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Strict-Transport-Security", "max-age=63072000")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("X-Frame-Options", "DENY")
		// The UIs are a Go wasm module and the script that starts it, all
		// from here. 'wasm-unsafe-eval' is what compiling a module needs;
		// nothing else is evaluated.
		hd.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "+
			"style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; "+
			"frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.ServeHTTP(w, r)
	})
}

// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"slices"
	"strings"
	"time"
)

// The WebDAV a server's shares are served over, passed through for the
// explorer: /dav/<server>/<share>/<path> is <dav_url>/<share>/<path> on that
// server, with the server's WebDAV token.
//
// ⛔ WHAT A SERVER RETURNS IS NOT TRUSTED AS A PAGE. A file on a share is
// whatever somebody put there -- an HTML page with a script, say -- and served
// from the portal's origin, that script would run as the portal: it cannot
// read the HttpOnly cookie, but it can call /api and /dav with the static
// header, as the person, which is everything. So a GET is always an
// attachment, of an opaque type, never sniffed, and sandboxed by its own
// Content-Security-Policy even if a browser rendered it anyway.

// davKey is where a server's WebDAV token is kept in the session, when its
// audience is not the admin API's.
const davKey = "/dav"

// davMethods are the ones passed through: browsing, downloading, uploading in
// pieces, and the namespace operations. Not LOCK, PROPPATCH or anything else.
var davMethods = []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodDelete,
	"PROPFIND", "MKCOL", "MOVE", "COPY"}

// maxPiece bounds a PUT through the portal: one piece of an upload. A larger
// file goes in pieces (an empty PUT, then appends; go-filesystems/webdav
// v0.6.0).
const maxPiece = 16 << 20

// maxPropfind bounds a PROPFIND body.
const maxPropfind = 64 << 10

type davTarget struct {
	base *url.URL
	rp   *httputil.ReverseProxy
}

func newDAV(servers []serverBlock) (map[string]*davTarget, error) {
	out := map[string]*davTarget{}
	for _, s := range servers {
		if s.DAVURL == "" {
			continue
		}
		u, err := url.Parse(strings.TrimSuffix(s.DAVURL, "/"))
		if err != nil {
			return nil, err
		}
		tc := &tls.Config{MinVersion: tls.VersionTLS12}
		if s.CAFile != "" {
			pem, err := os.ReadFile(s.CAFile)
			if err != nil {
				return nil, fmt.Errorf("server %q: %w", s.ID, err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("server %q: %s holds no certificate", s.ID, s.CAFile)
			}
			tc.RootCAs = pool
		}
		target := u
		out[s.ID] = &davTarget{base: u, rp: &httputil.ReverseProxy{
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
				TLSClientConfig:       tc,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 120 * time.Second,
				IdleConnTimeout:       90 * time.Second,
				ForceAttemptHTTP2:     true,
			},
			// The path is set by dav() below; the rest of the URL is the
			// server's.
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.Out.URL.Scheme, pr.Out.URL.Host = target.Scheme, target.Host
				pr.Out.Host = target.Host
			},
			ModifyResponse: inert,
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				jsonError(w, http.StatusBadGateway, "unavailable", "the server did not answer")
			},
			// Downloads stream: no buffering of a response here.
			FlushInterval: -1,
		}}
	}
	return out, nil
}

// inert makes what a server returns harmless on the portal's origin.
func inert(res *http.Response) error {
	h := res.Header
	h.Del("Set-Cookie")
	if r := res.Request; r != nil && (r.Method == http.MethodGet || r.Method == http.MethodHead) &&
		res.StatusCode < 300 {
		name := path.Base(r.URL.Path)
		h.Set("Content-Type", "application/octet-stream")
		h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	}
	// The server's own say on these is not taken: dav() has set the
	// portal's, and the proxy ADDS what the server sends -- a second policy
	// beside the first, not one in its place.
	for _, k := range []string{"Content-Security-Policy", "X-Content-Type-Options", "Cache-Control",
		"X-Frame-Options", "Referrer-Policy", "Strict-Transport-Security"} {
		h.Del(k)
	}
	return nil
}

// davHeaders are what every /dav answer carries, the portal's refusals
// included: a document that runs no script, loads nothing and sits in a
// unique origin, in place of the policy the UI pages get.
func davHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", "sandbox; default-src 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "private, no-store")
}

// dav is /dav/{server}/{path...}.
func (p *portal) dav(w http.ResponseWriter, r *http.Request) {
	davHeaders(w)
	if !slices.Contains(davMethods, r.Method) {
		w.Header().Set("Allow", strings.Join(davMethods, ", "))
		jsonError(w, http.StatusMethodNotAllowed, "unimplemented", "the portal passes "+strings.Join(davMethods, ", "))
		return
	}
	// A download is a navigation -- a link the explorer follows -- and a
	// navigation cannot carry the static header; it is also a GET, which
	// changes nothing. Every other method is called with fetch, and carries
	// it like /api does. A GET another site starts is refused all the same.
	safe := r.Method == http.MethodGet || r.Method == http.MethodHead
	if !safe && !p.fromPage(w, r) {
		return
	}
	if site := r.Header.Get("Sec-Fetch-Site"); safe && site != "" && site != "same-origin" && site != "none" {
		jsonError(w, http.StatusForbidden, "permission_denied", "a request from another site")
		return
	}
	id := r.PathValue("server")
	sb, t := p.servers[id], p.davTargets[id]
	if sb == nil || t == nil {
		jsonError(w, http.StatusNotFound, "not_found", "no such server, or it serves no WebDAV here")
		return
	}
	rel, ok := cleanDAVPath(r.PathValue("path"))
	if !ok {
		jsonError(w, http.StatusBadRequest, "invalid_argument", "a path with . or .. in it")
		return
	}
	s := p.sessions.read(r)
	if s == nil {
		jsonError(w, http.StatusUnauthorized, "unauthenticated", "not logged in")
		return
	}
	key := id
	if sb.davResource() != sb.Resource {
		key = id + davKey
	}
	tok, ok := s.Tokens[key]
	if !ok || !p.now().Add(15*time.Second).Before(tok.Expires) {
		// Not refreshed here, as for /api: see portal.refresh.
		w.Header().Set("Portal-Refresh", id)
		jsonError(w, http.StatusUnauthorized, "unauthenticated", "no current token for this server: refresh")
		return
	}

	out := r.Clone(r.Context())
	switch r.Method {
	case "PROPFIND":
		// RFC 4918 §9.1: a server may refuse infinity; this portal does, so
		// that one request cannot walk a whole share.
		d := r.Header.Get("Depth")
		if d != "0" && d != "1" {
			jsonError(w, http.StatusForbidden, "permission_denied", "PROPFIND with Depth 0 or 1 only")
			return
		}
		out.Body = http.MaxBytesReader(w, r.Body, maxPropfind)
	case http.MethodPut:
		if r.ContentLength > maxPiece {
			jsonError(w, http.StatusRequestEntityTooLarge, "resource_exhausted",
				"a PUT through the portal is at most 16 MiB: send a larger file in pieces")
			return
		}
		out.Body = http.MaxBytesReader(w, r.Body, maxPiece)
	case "MOVE", "COPY":
		dest, ok := p.davDestination(r.Header.Get("Destination"), id, t)
		if !ok {
			jsonError(w, http.StatusBadRequest, "invalid_argument", "Destination must be a path on the same server, under /dav/"+id+"/")
			return
		}
		out.Header.Set("Destination", dest)
	}
	// What the browser sent that a server could take for authority goes,
	// as for /api; the token is the one authority passed on.
	for _, h := range browserHeaders {
		out.Header.Del(h)
	}
	out.Header.Del("If") // lock tokens: the explorer takes no locks
	out.Header.Set("Authorization", "Bearer "+tok.Token)
	out.URL.Path = t.base.Path + "/" + rel
	out.URL.RawPath = ""
	out.URL.RawQuery = ""
	t.rp.ServeHTTP(w, out)
}

// cleanDAVPath refuses a path that names . or .., however encoded: the
// server would resolve them, and the portal decides which server and share a
// request is for by the path.
func cleanDAVPath(p string) (string, bool) {
	for seg := range strings.SplitSeq(p, "/") {
		if seg == "." || seg == ".." || strings.ContainsAny(seg, "\\\x00") {
			return "", false
		}
	}
	return strings.TrimPrefix(p, "/"), true
}

// davDestination rewrites a MOVE or COPY Destination from the portal's URL to
// the server's. It must name the portal, /dav/, and the same server: a copy
// from one server to another is not one request, and a destination elsewhere
// would make the server write wherever the request said.
func (p *portal) davDestination(dest, id string, t *davTarget) (string, bool) {
	u, err := url.Parse(dest)
	if err != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", false
	}
	if u.IsAbs() {
		if u.Scheme != p.cfg.public.Scheme || u.Host != p.cfg.public.Host {
			return "", false
		}
	} else if u.Host != "" {
		return "", false
	}
	rest, ok := strings.CutPrefix(u.Path, "/dav/"+id+"/")
	if !ok {
		return "", false
	}
	rel, ok := cleanDAVPath(rest)
	if !ok || rel == "" {
		return "", false
	}
	out := *t.base
	out.Path = t.base.Path + "/" + rel
	return out.String(), true
}

// fromPage is fetchOnly's check, for a handler that applies it to some
// methods only. It answers the refusal itself and says whether to go on.
func (p *portal) fromPage(w http.ResponseWriter, r *http.Request) bool {
	origin := strings.TrimSuffix(p.cfg.public.String(), "/")
	switch {
	case r.Header.Get(requestHeader) != "1":
		jsonError(w, http.StatusForbidden, "permission_denied", "a request the portal's pages did not send")
	case r.Header.Get("Origin") != "" && r.Header.Get("Origin") != origin:
		jsonError(w, http.StatusForbidden, "permission_denied", "a request from another origin")
	case r.Header.Get("Sec-Fetch-Site") != "" && r.Header.Get("Sec-Fetch-Site") != "same-origin":
		jsonError(w, http.StatusForbidden, "permission_denied", "a request from another site")
	default:
		return true
	}
	return false
}

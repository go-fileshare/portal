// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

// A proxy passes a UI's Connect call to the fileshare server it names, with
// the access token the session holds for that server, and nothing else of the
// browser's: not its cookies, not its own Authorization, not its address
// claims.
//
// Only the admin service is reachable, by its procedure paths
// (/fileshare.admin.v1.AdminService/<Method>): the portal is not a way to
// reach whatever else a server's listener answers.
type proxy struct {
	targets map[string]*httputil.ReverseProxy
}

// adminService is the one Connect service passed through.
const adminService = "fileshare.admin.v1.AdminService/"

// maxCall bounds a call's body, as fileshare's own listener does.
const maxCall = 1 << 20

func newProxy(servers []serverBlock) (*proxy, error) {
	p := &proxy{targets: map[string]*httputil.ReverseProxy{}}
	for _, s := range servers {
		u, err := url.Parse(s.URL)
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
		tr := &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSClientConfig:       tc,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConnsPerHost:   16,
			ForceAttemptHTTP2:     true,
		}
		target := u
		p.targets[s.ID] = &httputil.ReverseProxy{
			Transport: tr,
			// Rewrite starts from a copy with the hop-by-hop headers gone
			// and no X-Forwarded-*; api has already taken out the rest.
			Rewrite: func(pr *httputil.ProxyRequest) { pr.SetURL(target) },
			ModifyResponse: func(res *http.Response) error {
				// A server's cookie would be set on the PORTAL's origin.
				res.Header.Del("Set-Cookie")
				return nil
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				jsonError(w, http.StatusBadGateway, "unavailable", "the server did not answer")
			},
		}
	}
	return p, nil
}

// api is POST /api/{server}/{rpc...}.
func (p *portal) api(w http.ResponseWriter, r *http.Request) {
	id, rpc := r.PathValue("server"), r.PathValue("rpc")
	rp := p.proxy.targets[id]
	if rp == nil {
		jsonError(w, http.StatusNotFound, "not_found", "no such server")
		return
	}
	method, ok := strings.CutPrefix(rpc, adminService)
	if !ok || method == "" || strings.ContainsAny(method, "/?#%") {
		jsonError(w, http.StatusNotFound, "unimplemented", "the portal passes the admin service only")
		return
	}
	s := p.sessions.read(r)
	if s == nil {
		jsonError(w, http.StatusUnauthorized, "unauthenticated", "not logged in")
		return
	}
	t, ok := s.Tokens[id]
	// A token about to expire is treated as expired: it could expire on
	// the way.
	if !ok || !p.now().Add(15*time.Second).Before(t.Expires) {
		// Not refreshed here: see portal.refresh. The UI refreshes and
		// tries again.
		w.Header().Set("Portal-Refresh", id)
		jsonError(w, http.StatusUnauthorized, "unauthenticated", "no current token for this server: refresh")
		return
	}
	if r.ContentLength > maxCall {
		jsonError(w, http.StatusRequestEntityTooLarge, "resource_exhausted", "a call is at most 1 MiB")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxCall)
	out := r.Clone(r.Context())
	out.URL.Path = "/" + adminService + method
	out.URL.RawPath = ""
	// What is left of the browser's that a server could take for
	// authority goes; the one authority passed on is the token.
	for _, h := range browserHeaders {
		out.Header.Del(h)
	}
	out.Header.Set("Authorization", "Bearer "+t.Token)
	rp.ServeHTTP(w, out)
}

// browserHeaders are not passed to a server.
var browserHeaders = []string{"Cookie", "Authorization", requestHeader, "Origin", "Referer",
	"Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Forwarded",
	"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-Ip"}

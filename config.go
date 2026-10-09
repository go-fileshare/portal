// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
)

// A config is what the HCL file says.
//
//	listen     = "0.0.0.0:443"
//	public_url = "https://files.example.org"
//
//	tls {
//	  cert_file = "/etc/portal/tls/fullchain.pem"
//	  key_file  = "/etc/portal/tls/key.pem"
//	}
//
//	session {
//	  key_files = ["/etc/portal/session.key"]   # 32 random bytes each; the first seals
//	  lifetime  = "8h"
//	}
//
//	issuer "https://login.example.org" {
//	  client_id          = "fileshare-portal"
//	  client_secret_file = "/etc/portal/client.secret"
//	}
//
//	server "a" {
//	  label    = "Paris"
//	  url      = "https://fs-a.example.org:8443"   # the admin block's web listener
//	  issuer   = "https://login.example.org"
//	  resource = "https://fs-a.example.org:8443"   # RFC 8707: what the token is for
//	}
//
//	ui "console"  { dir = "/usr/share/fileshare-console" }
//	ui "explorer" { dir = "/usr/share/fileshare-explorer" }
//
// Every copy of the portal behind a load balancer reads the same file: the
// session is in the cookie, sealed with the same keys, so any copy can serve
// any request and none has to know about the others.
type config struct {
	Listen    string `hcl:"listen"`
	PublicURL string `hcl:"public_url"`

	TLS     *tlsBlock     `hcl:"tls,block"`
	Session sessionBlock  `hcl:"session,block"`
	Issuers []issuerBlock `hcl:"issuer,block"`
	Servers []serverBlock `hcl:"server,block"`
	UIs     []uiBlock     `hcl:"ui,block"`

	// public is PublicURL, parsed by check.
	public *url.URL
}

// tlsBlock is where the portal's own certificate comes from. Without one
// the portal listens in the clear, which check allows on loopback only: it
// is then behind something that terminates TLS for it.
type tlsBlock struct {
	CertFile string `hcl:"cert_file"`
	KeyFile  string `hcl:"key_file"`
}

type sessionBlock struct {
	// KeyFiles hold the keys that seal the cookies, 32 bytes each, raw or
	// base64. The FIRST seals; every one opens, so a key is replaced by
	// putting the new one first, and the old one is removed once every
	// session sealed with it has expired.
	KeyFiles []string `hcl:"key_files"`
	// Lifetime bounds a session from the login, however active it is: the
	// identity provider is asked again after it. Default 8h.
	Lifetime string `hcl:"lifetime,optional"`
	// MaxCookieBytes bounds the session's cookies together. A browser sends
	// them all in ONE Cookie header line, and nginx refuses a line over
	// 8 KiB by default (large_client_header_buffers 4 8k), so the default,
	// 7600, fits under it. Measured, that holds the tokens of 8 servers at
	// once when a token is 600 bytes, 5 at 1000 bytes, 3 at 1500. Raise it
	// with the load balancer's limit, up to 45600.
	MaxCookieBytes int `hcl:"max_cookie_bytes,optional"`

	keys     [][]byte
	lifetime time.Duration
}

type issuerBlock struct {
	URL              string `hcl:"url,label"`
	ClientID         string `hcl:"client_id"`
	ClientSecretFile string `hcl:"client_secret_file"`
	// Scopes asked for at the login. Default openid, profile and
	// offline_access (a refresh token is how the portal gets a token for
	// each server).
	Scopes []string `hcl:"scopes,optional"`

	secret string
}

type serverBlock struct {
	ID     string `hcl:"id,label"`
	Label  string `hcl:"label,optional"`
	URL    string `hcl:"url"`
	Issuer string `hcl:"issuer"`
	// Resource is the RFC 8707 resource indicator the token for this server
	// is asked for with. It becomes the token's "aud", which must be the
	// audience the server's issuer block names.
	Resource string `hcl:"resource,optional"`
	// Scope is asked for instead of, or as well as, a resource -- for a
	// provider that does not implement RFC 8707 and sets the audience from a
	// scope (Keycloak's audience mappers do).
	Scope string `hcl:"scope,optional"`
	// CAFile verifies the server's certificate when it is not publicly
	// trusted.
	CAFile string `hcl:"ca_file,optional"`
}

type uiBlock struct {
	Name string `hcl:"name,label"`
	Dir  string `hcl:"dir"`
}

// uiNames are the UIs the portal knows how to serve.
var uiNames = []string{"console", "explorer"}

// loadConfig reads and checks path. Secrets are read from the files the
// configuration names, never from the configuration itself.
func loadConfig(path string) (*config, error) {
	parser := hclparse.NewParser()
	f, diags := parser.ParseHCLFile(path)
	if diags.HasErrors() {
		return nil, diagError(parser, diags)
	}
	var cfg config
	if diags := gohcl.DecodeBody(f.Body, nil, &cfg); diags.HasErrors() {
		return nil, diagError(parser, diags)
	}
	if err := cfg.check(); err != nil {
		return nil, err
	}
	if err := cfg.readSecrets(filepath.Dir(path)); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func diagError(parser *hclparse.Parser, diags hcl.Diagnostics) error {
	var b strings.Builder
	wr := hcl.NewDiagnosticTextWriter(&b, parser.Files(), 0, false)
	_ = wr.WriteDiagnostics(diags)
	return errors.New(strings.TrimSpace(b.String()))
}

// check refuses what could not work, or would let in more than it says.
func (c *config) check() error {
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return fmt.Errorf("listen %q is not an address: %w", c.Listen, err)
	}
	if c.TLS == nil && !isLoopback(host) {
		// ⛔ The cookie is the session: in the clear, it is anybody's.
		return fmt.Errorf("listen %q without a tls block: only loopback may be served in the clear, behind something that terminates TLS", c.Listen)
	}
	u, err := url.Parse(c.PublicURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		// https, always: the session cookie is __Host-, which a browser
		// accepts only from a secure origin, at the root.
		return fmt.Errorf("public_url %q must be an https origin with no path, query or fragment", c.PublicURL)
	}
	c.public = u

	if len(c.Session.KeyFiles) == 0 {
		return errors.New("session: key_files is empty: there would be no key to seal the cookie with")
	}
	c.Session.lifetime = 8 * time.Hour
	if c.Session.Lifetime != "" {
		d, err := time.ParseDuration(c.Session.Lifetime)
		if err != nil || d <= 0 || d > 7*24*time.Hour {
			return fmt.Errorf("session: lifetime %q must be a duration between 0 and 168h", c.Session.Lifetime)
		}
		c.Session.lifetime = d
	}

	switch m := c.Session.MaxCookieBytes; {
	case m == 0:
		c.Session.MaxCookieBytes = 2 * chunkSize
	case m < chunkSize || m > maxChunks*chunkSize:
		return fmt.Errorf("session: max_cookie_bytes %d must be between %d and %d", m, chunkSize, maxChunks*chunkSize)
	}

	if len(c.Issuers) == 0 {
		return errors.New("no issuer block: nobody could log in")
	}
	var issuers []string
	for i := range c.Issuers {
		is := &c.Issuers[i]
		if slices.Contains(issuers, is.URL) {
			return fmt.Errorf("issuer %q is given twice", is.URL)
		}
		issuers = append(issuers, is.URL)
		if err := httpsOrLoopback(is.URL); err != nil {
			return fmt.Errorf("issuer %q: %w", is.URL, err)
		}
		if is.ClientID == "" {
			return fmt.Errorf("issuer %q: client_id is empty", is.URL)
		}
		if len(is.Scopes) == 0 {
			is.Scopes = []string{"openid", "profile", "offline_access"}
		}
		if !slices.Contains(is.Scopes, "openid") {
			return fmt.Errorf("issuer %q: scopes must include openid", is.URL)
		}
	}

	if len(c.Servers) == 0 {
		return errors.New("no server block: there would be nothing to manage")
	}
	var ids []string
	for _, s := range c.Servers {
		if !validID(s.ID) {
			return fmt.Errorf("server %q: an id is 1 to 32 of a-z, 0-9 and -, as it appears in a path", s.ID)
		}
		if slices.Contains(ids, s.ID) {
			return fmt.Errorf("server %q is given twice", s.ID)
		}
		ids = append(ids, s.ID)
		if err := httpsOrLoopback(s.URL); err != nil {
			return fmt.Errorf("server %q: url: %w", s.ID, err)
		}
		if !slices.Contains(issuers, s.Issuer) {
			return fmt.Errorf("server %q: issuer %q has no issuer block", s.ID, s.Issuer)
		}
		if s.Resource == "" && s.Scope == "" {
			// ⛔ A token asked for without saying which server it is for
			// carries the client's default audience -- which, if it names
			// several servers, any of them can replay to the others (RFC
			// 8707 §3).
			return fmt.Errorf("server %q: neither resource nor scope: the token would not be addressed to this server alone", s.ID)
		}
		if s.Resource != "" {
			if r, err := url.Parse(s.Resource); err != nil || !r.IsAbs() || r.Fragment != "" {
				// RFC 8707 §2: an absolute URI, with no fragment.
				return fmt.Errorf("server %q: resource %q must be an absolute URI without a fragment", s.ID, s.Resource)
			}
		}
	}

	var uis []string
	for _, u := range c.UIs {
		if !slices.Contains(uiNames, u.Name) {
			return fmt.Errorf("ui %q: the portal serves %s", u.Name, strings.Join(uiNames, " and "))
		}
		if slices.Contains(uis, u.Name) {
			return fmt.Errorf("ui %q is given twice", u.Name)
		}
		uis = append(uis, u.Name)
		if !filepath.IsAbs(u.Dir) {
			return fmt.Errorf("ui %q: dir %q must be absolute", u.Name, u.Dir)
		}
	}
	return nil
}

// readSecrets reads the session keys and the client secrets. A relative
// path is relative to the configuration file.
func (c *config) readSecrets(base string) error {
	for _, p := range c.Session.KeyFiles {
		k, err := readKey(resolve(base, p))
		if err != nil {
			return fmt.Errorf("session: %w", err)
		}
		c.Session.keys = append(c.Session.keys, k)
	}
	for i := range c.Issuers {
		is := &c.Issuers[i]
		b, err := readSecretFile(resolve(base, is.ClientSecretFile))
		if err != nil {
			return fmt.Errorf("issuer %q: %w", is.URL, err)
		}
		is.secret = strings.TrimSpace(string(b))
		if is.secret == "" {
			return fmt.Errorf("issuer %q: %s is empty", is.URL, is.ClientSecretFile)
		}
	}
	return nil
}

func resolve(base, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(base, p)
}

// readSecretFile reads a file that holds a secret, refusing one that others
// may read: a secret anybody on the machine can read is not one.
func readSecretFile(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if secretModeTooOpen(fi.Mode()) {
		return nil, fmt.Errorf("%s may be read by others (mode %v): chmod 0600 or 0640", path, fi.Mode().Perm())
	}
	return os.ReadFile(path)
}

func validID(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// httpsOrLoopback refuses a URL a token or a key would cross in the clear.
func httpsOrLoopback(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	switch {
	case u.Scheme == "https" && u.Host != "":
		return nil
	case u.Scheme == "http" && isLoopback(u.Hostname()):
		return nil
	}
	return fmt.Errorf("%q is not an https URL", raw)
}

// SPDX-License-Identifier: BSD-3-Clause

// Package client is what a UI behind the portal needs of it: who is logged
// in, which servers they reach, and an HTTP client per server that carries
// the portal's static header and, when the portal says a server's token is
// missing or expiring, refreshes -- once, one refresh at a time -- and sends
// the request again.
//
// The go-fileshare console calls the admin API with it (Connect); the
// explorer, WebDAV. Neither sees a token: the portal holds them.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// A Server is one fileshare server the portal knows.
type Server struct {
	ID    string
	Label string
	// Reachable: its tokens come from the identity provider this session
	// logged in with.
	Reachable bool
	// DAV: the portal passes its WebDAV (/dav/<id>/...), so its files can be
	// browsed.
	DAV bool
}

// Name is how a UI shows the server.
func (s Server) Name() string {
	if s.Label != "" {
		return s.Label
	}
	return s.ID
}

// A Session is who is logged in, and which servers they can reach.
type Session struct {
	Issuer, Subject, Name string
	Expires               time.Time
	Servers               []Server
}

// Who is how a UI names the person.
func (s *Session) Who() string {
	if s.Name != "" {
		return s.Name
	}
	return s.Subject
}

var (
	// ErrNotLoggedIn: there is no session, or it has ended -- log in again.
	ErrNotLoggedIn = errors.New("not logged in")
	// ErrTooLarge: a request body over the Doer's bound, refused before it
	// is sent.
	ErrTooLarge = errors.New("the request is larger than the portal takes")
)

// RefreshError is a refresh the portal could not do -- the provider down,
// say -- which is not the end of the login.
type RefreshError struct{ Status string }

func (e *RefreshError) Error() string { return "portal: refresh: " + e.Status }

// RequestHeader is the static header the portal requires of every call its
// pages make with fetch (its CSRF defence).
const RequestHeader = "Portal-Request"

// MaxInUse is how many servers' tokens one refresh asks for: the ones most
// recently used. The portal keeps its session in cookies a load balancer
// bounds (8 KiB of header at nginx's default); five tokens of about 1 KB fit.
const MaxInUse = 5

// Portal is a client of go-fileshare/portal.
type Portal struct {
	base string
	hc   *http.Client
	// serialize runs a refresh with every other one -- across the tabs of a
	// browser where it can (the Web Locks API) -- so that the portal never
	// sees two at once: a provider that rotates refresh tokens ends the
	// login when one is spent twice.
	serialize func(func() error) error

	mu    sync.Mutex
	inUse []string // servers recently called, most recent first
	now   func() time.Time
}

// New is a client of the portal at base, an origin such as
// "https://files.example.org". serialize may be nil: refreshes are then
// serialized within this process only.
func New(base string, hc *http.Client, serialize func(func() error) error) *Portal {
	if hc == nil {
		hc = http.DefaultClient
	}
	p := &Portal{base: strings.TrimSuffix(base, "/"), hc: hc, now: time.Now}
	if serialize == nil {
		var mu sync.Mutex
		serialize = func(fn func() error) error {
			mu.Lock()
			defer mu.Unlock()
			return fn()
		}
	}
	p.serialize = serialize
	return p
}

// Base is the portal's origin.
func (p *Portal) Base() string { return p.base }

type sessionView struct {
	Issuer  string    `json:"issuer"`
	Subject string    `json:"subject"`
	Name    string    `json:"name"`
	Expires time.Time `json:"expires"`
	Servers []struct {
		ID        string     `json:"id"`
		Label     string     `json:"label"`
		Reachable bool       `json:"reachable"`
		DAV       bool       `json:"dav"`
		Token     *time.Time `json:"token_expires"`
	} `json:"servers"`
}

func (p *Portal) get(ctx context.Context) (*sessionView, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.base+"/session", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(RequestHeader, "1")
	res, err := p.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusUnauthorized {
		return nil, ErrNotLoggedIn
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("portal: %s", res.Status)
	}
	var v sessionView
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&v); err != nil {
		return nil, fmt.Errorf("portal: %w", err)
	}
	return &v, nil
}

// Session is who is logged in, or ErrNotLoggedIn.
func (p *Portal) Session(ctx context.Context) (*Session, error) {
	v, err := p.get(ctx)
	if err != nil {
		return nil, err
	}
	s := &Session{Issuer: v.Issuer, Subject: v.Subject, Name: v.Name, Expires: v.Expires}
	for _, sv := range v.Servers {
		s.Servers = append(s.Servers, Server{ID: sv.ID, Label: sv.Label, Reachable: sv.Reachable, DAV: sv.DAV})
	}
	return s, nil
}

// LoginURL is the portal's login, coming back to returnTo (a path).
func (p *Portal) LoginURL(returnTo string) string {
	return p.base + "/login?return=" + url.QueryEscape(returnTo)
}

// Logout ends the session, and returns where the browser should go next to
// end it at the identity provider too ("" if nowhere).
func (p *Portal) Logout(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.base+"/logout", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set(RequestHeader, "1")
	res, err := p.hc.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	var out struct {
		EndSession string `json:"end_session"`
	}
	_ = json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&out)
	return out.EndSession, nil
}

// used records that server was just called, and returns the servers whose
// tokens a refresh should ask for: it, and the others most recently used.
func (p *Portal) used(server string) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.inUse = slices.DeleteFunc(p.inUse, func(s string) bool { return s == server })
	p.inUse = slices.Insert(p.inUse, 0, server)
	if len(p.inUse) > MaxInUse {
		p.inUse = p.inUse[:MaxInUse]
	}
	return slices.Clone(p.inUse)
}

// refresh asks the portal for tokens for servers, unless -- another tab, or
// another call of this one, having refreshed meanwhile -- the session already
// holds a current token for need.
func (p *Portal) refresh(ctx context.Context, need string, servers []string) error {
	return p.serialize(func() error {
		v, err := p.get(ctx)
		if err != nil {
			return err
		}
		for _, sv := range v.Servers {
			if sv.ID == need && sv.Token != nil && sv.Token.After(p.now().Add(30*time.Second)) {
				return nil
			}
		}
		err = p.postRefresh(ctx, servers)
		var tooMany *tooLarge
		if errors.As(err, &tooMany) && len(servers) > 1 {
			// The tokens of all these do not fit: ask for the one needed.
			return p.postRefresh(ctx, []string{need})
		}
		return err
	})
}

type tooLarge struct{}

func (*tooLarge) Error() string { return "portal: too many servers at once" }

func (p *Portal) postRefresh(ctx context.Context, servers []string) error {
	body, _ := json.Marshal(map[string][]string{"servers": servers})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.base+"/session/refresh", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set(RequestHeader, "1")
	req.Header.Set("Content-Type", "application/json")
	res, err := p.hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<20))
	switch res.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized:
		return ErrNotLoggedIn
	case http.StatusRequestEntityTooLarge:
		return &tooLarge{}
	}
	return &RefreshError{Status: res.Status}
}

// EnsureToken makes sure the session holds a current token for server --
// before a download, which is a navigation: a navigation that meets "refresh
// first" cannot refresh and try again.
func (p *Portal) EnsureToken(ctx context.Context, server string) error {
	return p.refresh(ctx, server, p.used(server))
}

// Doer is the HTTP client of one server's requests through the portal.
type Doer struct {
	p       *Portal
	server  string
	maxBody int64
}

// Doer is an HTTP client for server's requests -- /api/<server>/... for the
// admin API, /dav/<server>/... for its files -- with bodies of at most maxBody
// bytes, kept so that a request can be sent again after a refresh.
func (p *Portal) Doer(server string, maxBody int64) *Doer {
	return &Doer{p: p, server: server, maxBody: maxBody}
}

// Do sends req with the static header. When the portal answers that the
// server's token is missing or expiring (401, Portal-Refresh), it refreshes
// and sends it once more. Errors are ErrNotLoggedIn, ErrTooLarge, a
// *RefreshError, or the transport's. Any other answer is returned as it is --
// a 401 without Portal-Refresh included: the portal saying nobody is logged
// in, or a server refusing its token, which the caller tells apart.
func (d *Doer) Do(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		b, err := io.ReadAll(io.LimitReader(req.Body, d.maxBody+1))
		req.Body.Close()
		if err != nil {
			return nil, err
		}
		if int64(len(b)) > d.maxBody {
			return nil, ErrTooLarge
		}
		body = b
	}
	servers := d.p.used(d.server)
	send := func() (*http.Response, error) {
		r := req.Clone(req.Context())
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		r.Header.Set(RequestHeader, "1")
		return d.p.hc.Do(r)
	}
	res, err := send()
	if err != nil || res.StatusCode != http.StatusUnauthorized || res.Header.Get("Portal-Refresh") == "" {
		return res, err
	}
	res.Body.Close()
	if err := d.p.refresh(req.Context(), d.server, servers); err != nil {
		return nil, err
	}
	return send()
}

// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"net/http"
	"time"

	"github.com/go-authn/oidc"
	"github.com/go-authn/rp"
)

// A provider is one OpenID provider the portal logs people in with, as a
// confidential client. The protocol is go-authn/rp's: discovery checked
// (issuer exact, endpoints https or loopback, S256 offered), PKCE S256, state,
// nonce, the ID token verified with its nonce and azp, client_secret_basic,
// and refresh for one resource at a time (RFC 8707 §2.2).
type provider struct {
	cfg *issuerBlock
	c   *rp.Client
}

func newProvider(ctx context.Context, cfg *issuerBlock, redirect string, client *http.Client) (*provider, error) {
	p, err := rp.Discover(ctx, client, cfg.URL)
	if err != nil {
		return nil, err
	}
	c, err := rp.NewClient(ctx, p, rp.Config{ClientID: cfg.ClientID, Secret: cfg.secret, RedirectURI: redirect, Scopes: cfg.Scopes})
	if err != nil {
		return nil, err
	}
	return &provider{cfg: cfg, c: c}, nil
}

// start begins a login: the flow to remember, and where to send the browser.
func (p *provider) start(now time.Time, ret string) (*flow, string) {
	f := rp.NewFlow()
	return &flow{Issuer: p.cfg.URL, State: f.State, Nonce: f.Nonce, Verifier: f.Verifier,
		Return: ret, Expires: now.Add(flowLifetime)}, p.c.AuthCodeURL(f, nil)
}

// login exchanges the code for tokens, and verifies the ID token against the
// flow's nonce.
func (p *provider) login(ctx context.Context, code string, f *flow) (*rp.Token, *oidc.Token, error) {
	return p.c.Exchange(ctx, code, rp.Flow{State: f.State, Nonce: f.Nonce, Verifier: f.Verifier})
}

// buy buys an access token with the refresh token: for one server's admin
// API, or its WebDAV, as f says.
func (p *provider) buy(ctx context.Context, rt string, f rp.For) (*rp.Token, error) {
	return p.c.Refresh(ctx, rt, f)
}

// endSession is where to end the session at the provider, or "".
func (p *provider) endSession(postLogout string) string { return p.c.EndSessionURL(postLogout) }

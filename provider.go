// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-authn/oidc"
)

// A provider is one OpenID provider the portal logs people in with, as a
// confidential client: authorization code, PKCE (S256), nonce, and the
// client's secret at the token endpoint (RFC 6749 §2.3.1, client_secret_basic).
//
// This is the half go-authn/oidc deliberately leaves out -- it verifies
// tokens and gets nobody one. The ID token is verified with it.
type provider struct {
	cfg      *issuerBlock
	authURL  string
	tokenURL string
	endURL   string // end_session_endpoint, if the provider has one
	idTokens *oidc.Verifier
	client   *http.Client
	redirect string // the callback, under public_url
}

// discovery is the part of /.well-known/openid-configuration used here.
type discovery struct {
	Issuer  string   `json:"issuer"`
	Auth    string   `json:"authorization_endpoint"`
	Token   string   `json:"token_endpoint"`
	EndSess string   `json:"end_session_endpoint"`
	Methods []string `json:"code_challenge_methods_supported"`
}

func newProvider(ctx context.Context, cfg *issuerBlock, redirect string, client *http.Client) (*provider, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(cfg.URL, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery: %s", res.Status)
	}
	var d discovery
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&d); err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	// OIDC Discovery §4.3: the issuer in the document must be the one it was
	// fetched for, exactly; otherwise one provider could speak for another.
	if d.Issuer != cfg.URL {
		return nil, fmt.Errorf("discovery: the document says issuer %q, not %q", d.Issuer, cfg.URL)
	}
	for _, u := range []string{d.Auth, d.Token} {
		if err := httpsOrLoopback(u); err != nil {
			return nil, fmt.Errorf("discovery: %w", err)
		}
	}
	if d.EndSess != "" && httpsOrLoopback(d.EndSess) != nil {
		d.EndSess = ""
	}
	// A provider that publishes its PKCE methods without S256 would ignore
	// the challenge, and the code would be good to whoever intercepted it.
	if d.Methods != nil && !slices.Contains(d.Methods, "S256") {
		return nil, errors.New("discovery: the provider does not offer PKCE with S256")
	}
	v, err := oidc.New(ctx, oidc.Config{Issuer: cfg.URL, Audience: cfg.ClientID, Client: client})
	if err != nil {
		return nil, err
	}
	return &provider{cfg: cfg, authURL: d.Auth, tokenURL: d.Token, endURL: d.EndSess,
		idTokens: v, client: client, redirect: redirect}, nil
}

// start begins a login: the flow to remember, and where to send the browser.
func (p *provider) start(now time.Time, ret string) (*flow, string) {
	f := &flow{Issuer: p.cfg.URL, State: random(), Nonce: random(), Verifier: random(),
		Return: ret, Expires: now.Add(flowLifetime)}
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {p.cfg.ClientID},
		"redirect_uri":          {p.redirect},
		"scope":                 {strings.Join(p.cfg.Scopes, " ")},
		"state":                 {f.State},
		"nonce":                 {f.Nonce},
		"code_challenge":        {challenge(f.Verifier)},
		"code_challenge_method": {"S256"},
	}
	sep := "?"
	if strings.Contains(p.authURL, "?") {
		sep = "&"
	}
	return f, p.authURL + sep + q.Encode()
}

// tokenResponse is RFC 6749 §5.1, and the ID token OIDC Core §3.1.3.3 adds.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

// A tokenError is the provider's refusal (RFC 6749 §5.2). invalid_grant
// means the grant is over: the person has to log in again.
type tokenError struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (e *tokenError) Error() string {
	if e.Description != "" {
		return e.Code + ": " + e.Description
	}
	return e.Code
}

func (p *provider) exchange(ctx context.Context, code, verifier string) (*tokenResponse, error) {
	return p.token(ctx, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {p.redirect},
		"code_verifier": {verifier},
	})
}

// refresh buys an access token for one server with the refresh token: its
// resource (RFC 8707 §2.2 -- the token is for that one, while the refresh
// token keeps the whole grant) and/or its scope.
func (p *provider) refresh(ctx context.Context, rt string, s *serverBlock) (*tokenResponse, error) {
	v := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}
	if s.Resource != "" {
		v.Set("resource", s.Resource)
	}
	if s.Scope != "" {
		v.Set("scope", s.Scope)
	}
	return p.token(ctx, v)
}

func (p *provider) token(ctx context.Context, form url.Values) (*tokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// RFC 6749 §2.3.1: both are form-encoded BEFORE they go into Basic.
	req.SetBasicAuth(url.QueryEscape(p.cfg.ClientID), url.QueryEscape(p.cfg.secret))
	res, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		var te tokenError
		if json.Unmarshal(body, &te) == nil && te.Code != "" {
			return nil, &te
		}
		return nil, fmt.Errorf("token endpoint: %s", res.Status)
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("token endpoint: %w", err)
	}
	if tr.AccessToken == "" || !strings.EqualFold(tr.TokenType, "Bearer") {
		return nil, fmt.Errorf("token endpoint: no bearer access token in the answer")
	}
	return &tr, nil
}

// verifyID checks the ID token of a login: signature, issuer, audience (the
// client), times -- go-authn/oidc -- and the nonce this browser's flow sent,
// so that an ID token from another login cannot be played into this one
// (OIDC Core §3.1.3.7).
func (p *provider) verifyID(ctx context.Context, raw, nonce string) (*oidc.Token, error) {
	tok, err := p.idTokens.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	var got string
	if err := tok.Claim("nonce", &got); err != nil || got == "" || got != nonce {
		return nil, errors.New("the ID token does not carry this login's nonce")
	}
	// §3.1.3.7 (4, 5): with more than one audience, azp must be this client.
	if aud := tok.Audience(); len(aud) > 1 {
		var azp string
		if tok.Claim("azp", &azp) != nil || azp != p.cfg.ClientID {
			return nil, errors.New("the ID token has several audiences and is not authorised to this client")
		}
	}
	return tok, nil
}

// random is 32 bytes from the system's generator, base64url: a state, a
// nonce, a PKCE verifier (RFC 7636 §4.1: 43 characters, the minimum, of 256
// bits).
func random() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// challenge is S256 (RFC 7636 §4.2).
func challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

# portal

The server behind the go-fileshare UIs. It logs people in with OpenID
Connect, keeps their session in a sealed cookie, buys a token for each
[fileshare](https://github.com/go-fileshare/fileshare) server, and passes the
UIs' Connect calls to those servers with the right token. **The browser never
holds a token.** Pure Go, `CGO_ENABLED=0`, one binary.

```sh
go install github.com/go-fileshare/portal@latest
portal -config /etc/portal/portal.hcl
```

It keeps no state. Run as many copies as availability needs, behind any load
balancer, with the same configuration and the same session keys: any copy
serves any request.

This is phase 2 of the [UI design](https://github.com/go-fileshare/fileshare/blob/main/docs/ui.md).
The admin console and the file explorer, the two UIs it serves, are phases 3
and 4.

## Why a server in the middle

[draft-ietf-oauth-browser-based-apps-27](https://datatracker.ietf.org/doc/draft-ietf-oauth-browser-based-apps/)
§6.1 calls this a *backend for frontend* and recommends it for applications that
handle personal data. A token held by JavaScript or wasm can be read by any
script that runs in the page; a token held by the portal cannot. The page has a
cookie that is `HttpOnly`, so script cannot read it, and sealed, so its holder
learns nothing from it.

## Configuration

```hcl
listen     = "0.0.0.0:443"
public_url = "https://files.example.org"     # the callback is public_url + /callback

tls {
  cert_file = "/etc/portal/tls/fullchain.pem"   # re-read when it changes
  key_file  = "/etc/portal/tls/key.pem"
}

session {
  key_files        = ["/etc/portal/session.key"]   # openssl rand -base64 32 > session.key; chmod 600
  lifetime         = "8h"                          # from the login, however active
  max_cookie_bytes = 7600                          # see "Cookies" below
}

issuer "https://login.example.org" {
  client_id          = "fileshare-portal"
  client_secret_file = "/etc/portal/client.secret"
  # scopes = ["openid", "profile", "offline_access"]   # the default
}

server "paris" {
  label    = "Paris"
  url      = "https://fs-paris.example.org:8443"   # fileshare's admin { web { listen } }
  issuer   = "https://login.example.org"
  resource = "https://fs-paris.example.org/"       # RFC 8707: the token's audience
  # ca_file = "/etc/portal/fs-ca.pem"              # if its certificate is not publicly trusted
}

server "lyon" {
  url      = "https://fs-lyon.example.org:8443"
  issuer   = "https://login.example.org"
  resource = "https://fs-lyon.example.org/"
}

ui "console"  { dir = "/usr/share/fileshare-console" }
ui "explorer" { dir = "/usr/share/fileshare-explorer" }
```

On each fileshare server, the `issuer` block's `audience` is that server's
`resource` here
([fileshare's admin API over HTTPS](https://github.com/go-fileshare/fileshare#the-admin-api-over-https-for-oidc-tokens)):

```hcl
admin {
  web {
    listen = "0.0.0.0:8443"
    issuer "https://login.example.org" {
      audience = "https://fs-paris.example.org/"
      groups   = ["fileshare-admins"]
    }
  }
}
```

`portal -check -config …` reads the configuration and every secret it names,
and exits.

### What it refuses to start with

- a listener in the clear anywhere but loopback (behind something that
  terminates TLS), and a `public_url` that is not an https origin: the cookie
  is the session;
- an issuer, a server or a provider endpoint in the clear (loopback aside);
- a server with neither `resource` nor `scope`: its token would carry the
  client's default audience, and a token addressed to several servers can be
  replayed by any of them to the others (RFC 8707 §3);
- a secret file that others may read, a session key that is not 32 bytes;
- a provider whose discovery document names another issuer, or that offers
  PKCE without S256;
- an issuer it cannot reach: discovery and the keys are read at start.

## The provider

The portal is a **confidential client** using the authorization code flow
with PKCE (S256), `state`, `nonce`, and its secret at the token endpoint
(`client_secret_basic`). It needs:

- **refresh tokens** for the client (`offline_access`, or the provider's
  equivalent). The login's own access token is not used: each server's token
  is bought with the refresh token. A login that brings no refresh token is
  refused, with the reason in the log;
- a token **addressed to one server at a time**. The portal asks with the
  server's `resource` (RFC 8707 §2.2, on the refresh grant), or its `scope`
  for a provider that sets the audience from a scope instead, as Keycloak's
  audience mappers do;
- `https://<public_url>/callback` as a redirect URI.

## How tokens move

```
browser ── cookie ──► portal ── Bearer <token for paris> ──► fileshare paris
                        │
                        └──── Bearer <token for lyon> ───► fileshare lyon
```

1. `GET /login` sends the browser to the provider; `/callback` checks the
   answer — state, issuer (RFC 9207), the code exchanged with the PKCE
   verifier, the ID token's signature, audience and nonce — and stores the
   session: who, until when, and the refresh token.
2. `POST /session/refresh {"servers": ["paris", "lyon"]}` buys a token for
   each server named, one after the other, and keeps those alone.
3. `POST /api/paris/fileshare.admin.v1.AdminService/<Method>` is passed to
   that server with its token. Only the admin service is passed.

**The refresh token is spent in one place.** A provider that rotates refresh
tokens revokes the whole grant when a retired one comes back (RFC 9700
§4.14.2), and two requests refreshing at once would do exactly that. So the
proxy never refreshes. When a server's token is missing or about to expire it
answers `unauthenticated` with a `Portal-Refresh: <server>` header, and the UI
calls `/session/refresh` and tries again — one refresh at a time across its
tabs, with the browser's Web Locks API. If a refresh is lost anyway (the
answer never reaches the browser), the grant ends and the person logs in
again: the failure is a login, never a token that works for someone else.

## Cookies

| | |
|---|---|
| `__Host-Http-portal.0`, `.1`, … | the session, sealed (AES-256-GCM, the cookie name as associated data). `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, no `Domain` |
| `__Host-Http-portal-flow` | the login in progress, for ten minutes. `SameSite=Lax`, because the callback is a navigation coming from the provider's site |

`__Host-` makes the browser refuse the cookie unless it is `Secure`, at `/`,
and has no `Domain`, so no sibling host can set or read it. `-Http-` marks it
as set over HTTP, never by script (draft-ietf-httpbis-layered-cookies). A
browser that does not know that second prefix still enforces `__Host-`.

**A session spreads over several cookies**, because the tokens of several
servers outgrow the 4096 bytes a browser need keep of one (RFC 6265 §6.1).
A browser sends them all in one `Cookie` header line, and nginx refuses a line
over 8 KiB by default (`large_client_header_buffers 4 8k`). So
`max_cookie_bytes` defaults to 7600. Measured, that holds the tokens of 8
servers at once when a token is 600 bytes, 5 at 1000 bytes and 3 at 1500. The
UI asks for the servers it is showing, so this is a limit on servers *in view*,
not on servers configured. Raise it together with the load balancer's limit,
up to 45600; past it, a refresh is refused (`resource_exhausted`) rather than
half stored.

**Session keys.** The first key in `key_files` seals; every key opens. To
replace one, put the new key first, deploy it everywhere, and remove the old
key once every session sealed with it has expired (`lifetime`).

## Cross-site requests

Everything the UI calls with `fetch` must carry `Portal-Request: 1`. A page on
another origin cannot add that header without a CORS preflight, and the portal
answers none. When the browser says where a request comes from (`Origin`,
`Sec-Fetch-Site`), it must be the portal's own origin. Together with
`SameSite=Strict`, this is the defence of BBA-27 §6.1.3.3. The UIs are served
from the portal's origin, so none of this costs them a preflight.

What reaches a server is the call and the portal's token. The browser's
cookies, its `Authorization`, `Origin`, `Referer`, `Sec-Fetch-*` and any
`Forwarded`/`X-Forwarded-*` are removed, and a server's `Set-Cookie` is not
passed back. A call is at most 1 MiB, as on fileshare's own listener.

## Tests

```sh
go test ./...
go install github.com/go-fileshare/fileshare@v0.28.0
FILESHARE=$(go env GOPATH)/bin/fileshare go test -tags e2e -run E2E -v .
```

The unit tests run the whole flow against an OpenID provider written for them
(`idp_test.go`). It is strict where a real one is: exact redirect URI, PKCE
S256 only, rotating refresh tokens with reuse detection, and resource
indicators that become the only audience. Its servers verify their tokens with
go-authn/oidc, as fileshare does.

The `e2e` test puts the portal in front of **two real fileshare servers** and
checks four things:

- each server answers with the token bought for it;
- a share created on one server appears there and not on the other;
- the audit names the caller as `oidc=<issuer> <sub>` on the server that
  changed, and nobody on the other;
- each server refuses the other's token. The control is that it accepts its own.

Each defence was removed in turn, and a test failed each time: resource
indicator, header stripping, static header, `Origin`, `Sec-Fetch-Site`, nonce,
`state`, `iss`, `azp`, upstream `Set-Cookie`, the admin-service filter, keeping
the rotated refresh token, and `SameSite=Strict`.

## Not yet

- The UIs themselves: phases 3 and 4.
- The explorer's WebDAV through the portal (chunked `Content-Range` uploads).
- ACME for the portal's own certificate. go-authn/servercert has it; the
  configuration does not expose it yet.
- Servers behind different issuers in one session. A session belongs to one
  issuer, and `/session` lists the other issuers' servers as not reachable.
- RFC 8693 token exchange, for servers in another organisation.

## Licence

BSD 3-Clause.

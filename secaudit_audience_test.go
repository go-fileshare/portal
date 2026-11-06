// SPDX-License-Identifier: BSD-3-Clause

package main

import "testing"

// SECAUDIT 2026-11-05: config.go:257-263 refuses a server with neither
// resource nor scope "so that the token is addressed to this server alone",
// but accepts two servers addressed identically: the token the portal buys
// for one is then the token of the other, which its admins can replay there.
func TestSecauditTwoServersOneAudience(t *testing.T) {
	two := base + `
server "b" {
  url      = "https://fs-b.example.org:8443"
  issuer   = "https://login.example.org"
  resource = "https://fs-a.example.org:8443"
}
`
	if _, err := loadText(t, two); err == nil {
		t.Fatal("two servers with the same resource load: one server's token is valid at the other")
	}
}

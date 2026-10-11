// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/rand"
	"encoding/base64"

	"github.com/go-authn/rp"
)

// random and challenge, for the test provider (idp_test.go).
func random() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func challenge(verifier string) string { return rp.Challenge(verifier) }

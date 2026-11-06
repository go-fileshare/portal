// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"strings"
	"testing"
)

// A server's audience is its own: another server addressed by the same
// resource, spelled the same or not, by its WebDAV resource, or by the same
// scope, is refused at load.
func TestAudiencesMustBeDistinct(t *testing.T) {
	srv := func(id, extra string) string {
		return "\nserver \"" + id + "\" {\n  url = \"https://fs-" + id + ".example.org:8443\"\n  issuer = \"https://login.example.org\"\n" + extra + "\n}\n"
	}
	for name, add := range map[string]string{
		"same resource":                srv("b", `resource = "https://fs-a.example.org:8443"`),
		"trailing slash and host case": srv("b", `resource = "https://FS-A.example.org:8443/"`),
		"its dav resource is a's":      srv("b", "resource = \"https://fs-b.example.org:8443\"\ndav_url = \"https://fs-b.example.org:8444\"\ndav_resource = \"https://fs-a.example.org:8443\""),
		"the same scope, no resource":  srv("b", `scope = "fs"`) + srv("c", `scope = "fs"`),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadText(t, base+add)
			if err == nil {
				t.Fatal("two servers with one audience loaded")
			}
			// For the right reason: the audience, not a typo in the test's HCL.
			if !strings.Contains(err.Error(), "audience") {
				t.Fatalf("refused for another reason: %v", err)
			}
		})
	}
	// Distinct audiences, and a server whose dav resource is its own, load.
	ok := base + srv("b", "resource = \"https://fs-b.example.org:8443\"\ndav_url = \"https://fs-b.example.org:8444\"\ndav_resource = \"https://fs-b.example.org:8444\"")
	if _, err := loadText(t, ok); err != nil {
		t.Fatalf("distinct audiences: %v", err)
	}
}

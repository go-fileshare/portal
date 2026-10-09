// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// base is a configuration that loads; each case below changes one thing.
const base = `
listen     = "127.0.0.1:8080"
public_url = "https://files.example.org"
session {
  key_files = ["k"]
}
issuer "https://login.example.org" {
  client_id          = "portal"
  client_secret_file = "s"
}
server "a" {
  url      = "https://fs-a.example.org:8443"
  issuer   = "https://login.example.org"
  resource = "https://fs-a.example.org:8443"
}
`

func loadText(t *testing.T, text string) (*config, error) {
	t.Helper()
	dir := t.TempDir()
	writeSecret(t, filepath.Join(dir, "k"), strings.Repeat("k", 32))
	writeSecret(t, filepath.Join(dir, "s"), "secret")
	// An absolute directory, on whatever this runs on: "/x" is not one on
	// Windows. Backslashes doubled for an HCL string.
	text = strings.ReplaceAll(text, "@ABS@", strings.ReplaceAll(dir, `\`, `\\`))
	p := filepath.Join(dir, "portal.hcl")
	if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	return loadConfig(p)
}

func TestConfigLoads(t *testing.T) {
	c, err := loadText(t, base)
	if err != nil {
		t.Fatal(err)
	}
	if c.Session.lifetime.Hours() != 8 || c.Session.MaxCookieBytes != 7600 || len(c.Issuers[0].Scopes) != 3 || c.Issuers[0].secret != "secret" {
		t.Fatalf("%+v", c)
	}
	c, err = loadText(t, strings.Replace(base, `key_files = ["k"]`, `key_files = ["k"]
  lifetime = "1h"
  max_cookie_bytes = 20000`, 1)+"ui \"explorer\" { dir = \"@ABS@\" }\n")
	if err != nil || c.Session.lifetime.Hours() != 1 || c.Session.MaxCookieBytes != 20000 {
		t.Fatalf("%v %+v", err, c)
	}
}

func TestConfigRefusals(t *testing.T) {
	cases := map[string][2]string{
		"not HCL":                 {base, base + "}"},
		"unknown field":           {base, base + "colour = 1\n"},
		"listen not an address":   {`"127.0.0.1:8080"`, `"nowhere"`},
		"cleartext off loopback":  {`"127.0.0.1:8080"`, `"0.0.0.0:8080"`},
		"public_url in the clear": {`"https://files.example.org"`, `"http://files.example.org"`},
		"public_url with a path":  {`"https://files.example.org"`, `"https://files.example.org/portal"`},
		"public_url not a URL":    {`"https://files.example.org"`, `"https://files.example.org/%zz"`},
		"no session key":          {`key_files = ["k"]`, `key_files = []`},
		"lifetime nonsense":       {`key_files = ["k"]`, `key_files = ["k"]` + "\n lifetime = \"forever\""},
		"lifetime too long":       {`key_files = ["k"]`, `key_files = ["k"]` + "\n lifetime = \"200h\""},
		"cookie budget too small": {`key_files = ["k"]`, `key_files = ["k"]` + "\n max_cookie_bytes = 100"},
		"cookie budget too large": {`key_files = ["k"]`, `key_files = ["k"]` + "\n max_cookie_bytes = 99999"},
		"missing key file":        {`key_files = ["k"]`, `key_files = ["nope"]`},
		"missing secret file":     {`client_secret_file = "s"`, `client_secret_file = "nope"`},
		"no issuer":               {base, strings.Split(base, "issuer \"https://login")[0]},
		"issuer in the clear":     {`issuer "https://login.example.org" {`, `issuer "http://login.example.org" {`},
		"no client_id":            {`client_id          = "portal"`, `client_id = ""`},
		"no openid scope":         {`client_id          = "portal"`, `client_id = "portal"` + "\n scopes = [\"profile\"]"},
		"server id with a slash":  {`server "a"`, `server "a/b"`},
		"server id empty":         {`server "a"`, `server ""`},
		"server id too long":      {`server "a"`, `server "` + strings.Repeat("a", 33) + `"`},
		"server in the clear":     {`url      = "https://fs-a`, `url      = "http://fs-a`},
		"server of no issuer":     {`issuer   = "https://login.example.org"`, `issuer   = "https://other.example.org"`},
		"no resource, no scope":   {`resource = "https://fs-a.example.org:8443"`, ``},
		"resource not absolute":   {`resource = "https://fs-a.example.org:8443"`, `resource = "fs-a"`},
		"resource with fragment":  {`resource = "https://fs-a.example.org:8443"`, `resource = "https://fs-a.example.org/#x"`},
		"unknown ui":              {base, base + "ui \"shell\" { dir = \"@ABS@\" }\n"},
		"ui twice":                {base, base + "ui \"console\" { dir = \"@ABS@\" }\nui \"console\" { dir = \"@ABS@\" }\n"},
		"ui dir relative":         {base, base + "ui \"console\" { dir = \"x\" }\n"},
	}
	for name, c := range cases {
		text := strings.Replace(base, c[0], c[1], 1)
		if text == base && c[0] != base {
			t.Fatalf("%s: the case changes nothing", name)
		}
		_, err := loadText(t, text)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		t.Logf("%-24s %s", name, strings.SplitN(err.Error(), "\n", 2)[0])
	}
	issuerAgain := "issuer \"https://login.example.org\" {\n client_id = \"p\"\n client_secret_file = \"s\"\n}\n"
	if _, err := loadText(t, base+issuerAgain); err == nil {
		t.Error("an issuer given twice was accepted")
	}
	serverAgain := "server \"a\" {\n url = \"https://x.example.org\"\n issuer = \"https://login.example.org\"\n scope = \"x\"\n}\n"
	if _, err := loadText(t, base+serverAgain); err == nil {
		t.Error("a server given twice was accepted")
	}
	// A case accepted only because it is the base plus one block must load
	// when that block is right: the refusals above are for the reason named.
	ok := "server \"b\" {\n url = \"https://x.example.org\"\n issuer = \"https://login.example.org\"\n scope = \"x\"\n}\nui \"console\" { dir = \"@ABS@\" }\n"
	if _, err := loadText(t, base+ok); err != nil {
		t.Errorf("the control case: %v", err)
	}
	// An empty secret.
	dir := t.TempDir()
	writeSecret(t, filepath.Join(dir, "k"), strings.Repeat("k", 32))
	writeSecret(t, filepath.Join(dir, "s"), "\n")
	p := filepath.Join(dir, "portal.hcl")
	_ = os.WriteFile(p, []byte(base), 0o644)
	if _, err := loadConfig(p); err == nil {
		t.Error("an empty client secret was accepted")
	}
	if _, err := loadConfig(filepath.Join(dir, "none.hcl")); err == nil {
		t.Error("a missing file loaded")
	}
}

func TestHelpers(t *testing.T) {
	for in, want := range map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true, "10.0.0.1": false, "example.org": false} {
		if isLoopback(in) != want {
			t.Errorf("isLoopback(%q)", in)
		}
	}
	for in, ok := range map[string]bool{"https://a": true, "http://127.0.0.1:1": true, "http://a": false, "https://": false, "%zz": false} {
		if (httpsOrLoopback(in) == nil) != ok {
			t.Errorf("httpsOrLoopback(%q)", in)
		}
	}
	if resolve("/b", "/a") != "/a" || resolve("/b", "a") != filepath.Join("/b", "a") {
		t.Error("resolve")
	}
	if (&tokenError{Code: "x"}).Error() != "x" || (&tokenError{Code: "x", Description: "y"}).Error() != "x: y" {
		t.Error("tokenError")
	}
}

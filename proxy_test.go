// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProxyCAFile(t *testing.T) {
	dir := t.TempDir()
	cert, _ := selfSigned(t, dir)
	if _, err := newProxy([]serverBlock{{ID: "a", URL: "https://a", CAFile: cert}}); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty.pem")
	_ = os.WriteFile(empty, []byte("nothing"), 0o644)
	for _, s := range []serverBlock{
		{ID: "a", URL: "https://a", CAFile: filepath.Join(dir, "none.pem")},
		{ID: "a", URL: "https://a", CAFile: empty},
		{ID: "a", URL: "%zz"},
	} {
		if _, err := newProxy([]serverBlock{s}); err == nil {
			t.Errorf("%+v accepted", s)
		}
	}
}

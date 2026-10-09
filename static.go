// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"io"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"strings"
)

// static serves the UIs' files: /console/ and /explorer/, each from its
// directory, and / sends the browser to the first one configured.
//
// A Go wasm module is a few megabytes; built with a .gz beside it, that is
// what a browser that accepts gzip is sent (the module compresses about four
// to one). Everything is revalidated before use -- no-cache, not no-store --
// so that a new UI is picked up at the next load and an unchanged one costs
// a 304.
type static struct {
	uis   map[string]fs.FS
	first string
}

func newStatic(blocks []uiBlock) *static {
	s := &static{uis: map[string]fs.FS{}}
	for _, b := range blocks {
		s.uis[b.Name] = os.DirFS(b.Dir)
		if s.first == "" {
			s.first = b.Name
		}
	}
	return s
}

func (s *static) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path == "/" {
		if s.first == "" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/"+s.first+"/", http.StatusFound)
		return
	}
	name, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	fsys := s.uis[name]
	if fsys == nil {
		http.NotFound(w, r)
		return
	}
	if rest == "" && !strings.HasSuffix(r.URL.Path, "/") {
		http.Redirect(w, r, "/"+name+"/", http.StatusMovedPermanently)
		return
	}
	p := path.Clean("/" + rest)[1:]
	if p == "" {
		p = "index.html"
	}
	if !fs.ValidPath(p) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	if ct := mime.TypeByExtension(path.Ext(p)); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.Header().Add("Vary", "Accept-Encoding")
	if acceptsGzip(r) && serveFile(w, r, fsys, p+".gz", p, "gzip") {
		return
	}
	if !serveFile(w, r, fsys, p, p, "") {
		http.NotFound(w, r)
	}
}

// serveFile serves file as name, and says whether there was one to serve.
func serveFile(w http.ResponseWriter, r *http.Request, fsys fs.FS, file, name, encoding string) bool {
	f, err := fsys.Open(file)
	if err != nil {
		return false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return false
	}
	rs, ok := f.(io.ReadSeeker)
	if !ok {
		return false
	}
	if encoding != "" {
		w.Header().Set("Content-Encoding", encoding)
	}
	http.ServeContent(w, r, name, st.ModTime(), rs)
	return true
}

// acceptsGzip reads Accept-Encoding the way RFC 9110 §12.5.3 says: gzip,
// or *, unless its weight is 0.
func acceptsGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		coding, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		coding = strings.ToLower(strings.TrimSpace(coding))
		if coding != "gzip" && coding != "x-gzip" && coding != "*" {
			continue
		}
		q := strings.ReplaceAll(strings.ToLower(params), " ", "")
		if q == "q=0" || q == "q=0.0" || q == "q=0.00" || q == "q=0.000" {
			return false
		}
		return true
	}
	return false
}

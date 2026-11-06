// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// A session is sealed in the browser and nothing on the server says it is
// still wanted, so a copy of its cookie taken before a logout would open it
// again until the login's own end (up to 168 h). The portal therefore gives
// every session an id, and a logout puts that id in a revocation set that
// read consults: the set is the one thing the portal remembers.
//
// A revocation only has to be kept as long as the session could still open, so
// each entry carries the session's end and is dropped after it: the set is as
// large as the logouts of the last lifetime. It is bounded (maxRevocations);
// when it is full a logout is refused rather than forgotten.
//
// With revocations_file the set is appended to a file, so that it survives a
// restart exactly as the sessions do (they are sealed with keys, not held in
// memory), and a copy of the portal that shares the file -- on a shared volume
// -- sees the revocations of another within a second. Without it the set lives
// in memory, and a restart forgets it: check says so at start.

const (
	maxRevocations  = 100000
	revocationPoll  = time.Second
	sessionIDBytes  = 16
	revocationsMode = 0o600
)

var errRevocationsFull = errors.New("too many logouts still within their session lifetime")

type revocations struct {
	now  func() time.Time
	file string // "" keeps the set in memory

	mu      sync.Mutex
	ids     map[string]time.Time // session id -> end of the session
	checked time.Time            // the last time the file's change was looked for
	size    int64                // of the file, when it was read
	mtime   time.Time
}

// newRevocations reads the set a file holds (expired entries are dropped, and
// a file with some is rewritten without them).
func newRevocations(file string, now func() time.Time) (*revocations, error) {
	r := &revocations{now: now, file: file, ids: map[string]time.Time{}}
	if file == "" {
		return r, nil
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		return nil, fmt.Errorf("revocations_file: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.load(true); err != nil {
		return nil, fmt.Errorf("revocations_file: %w", err)
	}
	return r, nil
}

// load reads the file into the set, keeping the entries of this process that
// are not in it yet (none, in practice: every revoke is appended first). With
// compact, a file holding expired or malformed lines is rewritten. The caller
// holds r.mu.
func (r *revocations) load(compact bool) error {
	f, err := os.Open(r.file)
	if errors.Is(err, os.ErrNotExist) {
		r.size, r.mtime = 0, time.Time{}
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	now := r.now()
	ids := map[string]time.Time{}
	dropped := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 512), 512)
	for sc.Scan() {
		id, until, ok := parseRevocation(sc.Text())
		switch {
		case !ok || !until.After(now):
			dropped++
		case len(ids) >= maxRevocations:
			return errRevocationsFull
		default:
			ids[id] = until
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	r.ids, r.size, r.mtime = ids, st.Size(), st.ModTime()
	if compact && dropped > 0 {
		f.Close() // Windows does not rename over a file that is open
		return r.rewrite()
	}
	return nil
}

// parseRevocation reads "<id> <RFC 3339 end>".
func parseRevocation(line string) (string, time.Time, bool) {
	id, rest, ok := strings.Cut(line, " ")
	if !ok || !validSessionID(id) {
		return "", time.Time{}, false
	}
	until, err := time.Parse(time.RFC3339, rest)
	if err != nil {
		return "", time.Time{}, false
	}
	return id, until, true
}

func validSessionID(id string) bool {
	if len(id) != base64.RawURLEncoding.EncodedLen(sessionIDBytes) {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(id)
	return err == nil
}

// rewrite replaces the file by the set, atomically. The caller holds r.mu.
func (r *revocations) rewrite() error {
	tmp, err := os.CreateTemp(filepath.Dir(r.file), ".revocations-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	w := bufio.NewWriter(tmp)
	for id, until := range r.ids {
		fmt.Fprintf(w, "%s %s\n", id, until.UTC().Format(time.RFC3339))
	}
	if err := w.Flush(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(revocationsMode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), r.file); err != nil {
		return err
	}
	if st, err := os.Stat(r.file); err == nil {
		r.size, r.mtime = st.Size(), st.ModTime()
	}
	return nil
}

// revoke records that the session id is over, until its end. The entry is on
// disk (and synced) before it returns, so a crash after a logout does not
// bring the session back.
func (r *revocations) revoke(id string, until time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	for k, u := range r.ids { // the set holds what could still open, no more
		if !u.After(now) {
			delete(r.ids, k)
		}
	}
	if _, again := r.ids[id]; !again && len(r.ids) >= maxRevocations {
		return errRevocationsFull
	}
	if r.file != "" {
		f, err := os.OpenFile(r.file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, revocationsMode)
		if err != nil {
			return err
		}
		_, werr := fmt.Fprintf(f, "%s %s\n", id, until.UTC().Format(time.RFC3339))
		if werr == nil {
			werr = f.Sync()
		}
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return werr
		}
		if st, err := os.Stat(r.file); err == nil {
			r.size, r.mtime = st.Size(), st.ModTime()
		}
	}
	r.ids[id] = until
	return nil
}

// revoked reports whether the session id has been logged out.
func (r *revocations) revoked(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.poll()
	until, ok := r.ids[id]
	return ok && until.After(r.now())
}

// poll picks up the revocations another copy of the portal appended to the
// file, at most once a second. The caller holds r.mu.
func (r *revocations) poll() {
	if r.file == "" {
		return
	}
	now := r.now()
	if now.Sub(r.checked) < revocationPoll {
		return
	}
	r.checked = now
	st, err := os.Stat(r.file)
	if err != nil || (st.Size() == r.size && st.ModTime().Equal(r.mtime)) {
		return
	}
	_ = r.load(false) // on a read error the set stays as it was
}

// newSessionID is a session's id: 128 random bits.
func newSessionID() string {
	b := make([]byte, sessionIDBytes)
	if _, err := rand.Read(b); err != nil {
		panic(err) // no randomness, no seal either
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

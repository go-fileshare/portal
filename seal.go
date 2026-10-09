// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// A sealer encrypts what goes into a cookie and opens what comes back.
//
// AES-256-GCM, a random 96-bit nonce per seal, and the cookie's NAME as
// associated data: a value sealed for the login flow cookie does not open as
// a session, nor the reverse. Each key is known by the first 4 bytes of its
// SHA-256, carried in front of the nonce, so that opening tries the one key
// that sealed it rather than every key.
//
// The format is base64url(keyID[4] | nonce[12] | ciphertext+tag).
type sealer struct {
	keys []sealKey // keys[0] seals
}

type sealKey struct {
	id   [4]byte
	aead cipher.AEAD
}

const nonceSize = 12

var errUnsealed = errors.New("the cookie does not open")

func newSealer(keys [][]byte) (*sealer, error) {
	if len(keys) == 0 {
		return nil, errors.New("no session key")
	}
	s := &sealer{}
	for i, k := range keys {
		if len(k) != 32 {
			return nil, fmt.Errorf("session key %d is %d bytes, not 32", i+1, len(k))
		}
		block, err := aes.NewCipher(k)
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(k)
		var id [4]byte
		copy(id[:], sum[:4])
		for _, o := range s.keys {
			if o.id == id {
				return nil, fmt.Errorf("session key %d is given twice", i+1)
			}
		}
		s.keys = append(s.keys, sealKey{id: id, aead: aead})
	}
	return s, nil
}

func (s *sealer) seal(name string, plain []byte) string {
	k := s.keys[0]
	out := make([]byte, 4+nonceSize, 4+nonceSize+len(plain)+k.aead.Overhead())
	copy(out, k.id[:])
	_, _ = rand.Read(out[4 : 4+nonceSize])
	out = k.aead.Seal(out, out[4:4+nonceSize], plain, []byte(name))
	return base64.RawURLEncoding.EncodeToString(out)
}

func (s *sealer) open(name, sealed string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil || len(b) < 4+nonceSize {
		return nil, errUnsealed
	}
	for _, k := range s.keys {
		if !bytes.Equal(k.id[:], b[:4]) {
			continue
		}
		plain, err := k.aead.Open(nil, b[4:4+nonceSize], b[4+nonceSize:], []byte(name))
		if err != nil {
			return nil, errUnsealed
		}
		return plain, nil
	}
	return nil, errUnsealed
}

// readKey reads a session key: 32 bytes, raw or in standard or URL-safe
// base64 (what `openssl rand -base64 32` prints).
func readKey(path string) ([]byte, error) {
	b, err := readSecretFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) == 32 {
		return b, nil
	}
	t := bytes.TrimSpace(b)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		if k, err := enc.DecodeString(string(t)); err == nil && len(k) == 32 {
			return k, nil
		}
	}
	return nil, fmt.Errorf("%s does not hold a 32-byte key, raw or in base64 (openssl rand -base64 32)", path)
}

// secretModeTooOpen says whether a secret file's mode lets others read it.
// Mode bits do not describe access on Windows, so nothing is refused there.
var secretModeTooOpen = func(m fs.FileMode) bool {
	return osHasModeBits && m.Perm()&0o007 != 0
}

var osHasModeBits = os.PathSeparator == '/'

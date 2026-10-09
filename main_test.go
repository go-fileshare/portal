// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunCheck(t *testing.T) {
	w := newWorld(t)
	if err := run(filepath.Join(w.dir, "portal.hcl"), true); err != nil {
		t.Fatal(err)
	}
	if err := run(filepath.Join(w.dir, "none.hcl"), true); err == nil {
		t.Fatal("a missing configuration ran")
	}
}

// listen with a tls block serves the portal over TLS, from the files the
// block names, and offers h2.
func TestListenTLS(t *testing.T) {
	w := newWorld(t)
	cert, key := selfSigned(t, w.dir)
	w.cfg.TLS = &tlsBlock{CertFile: cert, KeyFile: key}
	srv, ln, err := listen(context.Background(), w.cfg, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	pool := x509.NewCertPool()
	pemBytes, _ := os.ReadFile(cert)
	pool.AppendCertsFromPEM(pemBytes)
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost"}, ForceAttemptHTTP2: true}}
	res, err := c.Get("https://" + ln.Addr().String() + "/console/")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK || res.ProtoMajor != 2 || res.Header.Get("Strict-Transport-Security") == "" {
		t.Fatalf("%s %s", res.Proto, res.Status)
	}

	// A pair that does not load, an address in use, an issuer that does
	// not answer: each stops the start.
	w.cfg.TLS = &tlsBlock{CertFile: key, KeyFile: cert}
	if _, _, err := listen(context.Background(), w.cfg, http.DefaultClient); err == nil {
		t.Fatal("a broken key pair started")
	}
	w.cfg.TLS = nil
	w.cfg.Listen = ln.Addr().String()
	if _, _, err := listen(context.Background(), w.cfg, http.DefaultClient); err == nil {
		t.Fatal("an address in use started")
	}
	w.cfg.Issuers[0].URL = "http://127.0.0.1:1"
	if _, _, err := listen(context.Background(), w.cfg, http.DefaultClient); err == nil || !strings.Contains(err.Error(), "issuer") {
		t.Fatalf("an unreachable issuer: %v", err)
	}
}

func selfSigned(t *testing.T, dir string) (string, string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalPKCS8PrivateKey(k)
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	_ = os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	writeSecret(t, key, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd})))
	return cert, key
}

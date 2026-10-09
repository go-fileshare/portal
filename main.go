// SPDX-License-Identifier: BSD-3-Clause

// Command portal is the server behind the go-fileshare UIs: it logs people
// in with OpenID Connect, keeps their session in a sealed cookie, buys a
// token for each fileshare server, and passes the UIs' Connect calls to the
// servers with those tokens. The browser never holds a token.
//
//	portal -config /etc/portal/portal.hcl
//
// It keeps no state: run as many copies as availability needs, behind any
// load balancer, with the same configuration and session keys.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-authn/servercert"
)

func main() {
	path := flag.String("config", "/etc/portal/portal.hcl", "the configuration file")
	check := flag.Bool("check", false, "read the configuration and the secrets it names, and exit")
	flag.Parse()
	if err := run(*path, *check); err != nil {
		fmt.Fprintln(os.Stderr, "portal:", err)
		os.Exit(1)
	}
}

func run(path string, check bool) error {
	cfg, err := loadConfig(path)
	if err != nil {
		return err
	}
	if check {
		fmt.Println("portal: the configuration is valid")
		return nil
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv, ln, err := listen(ctx, cfg, &http.Client{Timeout: 30 * time.Second})
	if err != nil {
		return err
	}
	log.Printf("portal: serving %s on %s", cfg.PublicURL, ln.Addr())
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shut)
}

// listen builds the portal and its listener: TLS from the tls block, the
// files re-read when they change (go-authn/servercert), or cleartext on
// loopback behind something that terminates TLS.
func listen(ctx context.Context, cfg *config, client *http.Client) (*http.Server, net.Listener, error) {
	p, err := newPortal(ctx, cfg, client)
	if err != nil {
		return nil, nil, err
	}
	srv := &http.Server{
		Handler:           p.handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10, // the session cookies, and room to spare
		ErrorLog:          log.New(os.Stderr, "portal: http: ", 0),
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return nil, nil, err
	}
	if cfg.TLS != nil {
		src, err := servercert.New(servercert.Config{CertFile: cfg.TLS.CertFile, KeyFile: cfg.TLS.KeyFile,
			OnError: func(err error) { log.Printf("portal: tls: %v", err) }})
		if err != nil {
			ln.Close()
			return nil, nil, errors.Join(errors.New("tls"), err)
		}
		tc := src.TLSConfig()
		tc.NextProtos = append(tc.NextProtos, "h2", "http/1.1")
		srv.TLSConfig = tc
		ln = tls.NewListener(ln, tc)
	}
	return srv, ln, nil
}

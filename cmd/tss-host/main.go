package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/juno-intents/intents-juno/internal/tsshost"
)

func main() {
	var signerArgs multiValueFlag

	var (
		listenAddr = flag.String("listen-addr", "127.0.0.1:8443", "listen address")

		tlsCertFile  = flag.String("tls-cert-file", "", "server TLS cert PEM file (required unless --insecure-http)")
		tlsKeyFile   = flag.String("tls-key-file", "", "server TLS key PEM file (required unless --insecure-http)")
		clientCAFile = flag.String("client-ca-file", "", "client CA PEM file (enables mTLS when set)")

		insecureHTTP       = flag.Bool("insecure-http", false, "serve plain HTTP (DANGEROUS; dev only)")
		signerBin          = flag.String("signer-bin", "", "path to signer command binary (required; typically tss-signer)")
		signerMaxRespBytes = flag.Int("signer-max-response-bytes", 1<<20, "max signer response size (bytes)")

		maxBodyBytes   = flag.Int64("max-body-bytes", 1<<20, "max HTTP request body size (bytes)")
		maxTxPlanBytes = flag.Int("max-txplan-bytes", 1<<20, "max decoded txPlan size (bytes)")
		maxSessions    = flag.Int("max-sessions", 1024, "max in-memory sessions for idempotency")

		readHeaderTimeout = flag.Duration("read-header-timeout", 5*time.Second, "http.Server ReadHeaderTimeout")
		readTimeout       = flag.Duration("read-timeout", 10*time.Second, "http.Server ReadTimeout")
		writeTimeout      = flag.Duration("write-timeout", 10*time.Second, "http.Server WriteTimeout")
		idleTimeout       = flag.Duration("idle-timeout", 60*time.Second, "http.Server IdleTimeout")
	)
	flag.Var(&signerArgs, "signer-arg", "argument passed to signer binary (repeatable)")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *listenAddr == "" {
		log.Error("missing --listen-addr")
		os.Exit(2)
	}
	if *maxBodyBytes <= 0 || *maxTxPlanBytes <= 0 || *maxSessions <= 0 {
		log.Error("invalid size limits")
		os.Exit(2)
	}
	if *signerMaxRespBytes <= 0 {
		log.Error("invalid signer limits")
		os.Exit(2)
	}
	if *signerBin == "" {
		log.Error("missing --signer-bin")
		os.Exit(2)
	}

	signer, err := tsshost.NewExecSigner(*signerBin, signerArgs.Values(), *signerMaxRespBytes)
	if err != nil {
		log.Error("init signer", "err", err)
		os.Exit(2)
	}

	h := tsshost.NewHandler(signer, tsshost.Config{
		MaxBodyBytes:   *maxBodyBytes,
		MaxTxPlanBytes: *maxTxPlanBytes,
		MaxSessions:    *maxSessions,
		Now:            time.Now,
	})

	srv := &http.Server{
		Addr:              *listenAddr,
		Handler:           h,
		ReadHeaderTimeout: *readHeaderTimeout,
		ReadTimeout:       *readTimeout,
		WriteTimeout:      *writeTimeout,
		IdleTimeout:       *idleTimeout,
		MaxHeaderBytes:    1 << 20,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		log.Info("tss-host starting", "addr", *listenAddr, "tls", !*insecureHTTP, "mtls", *clientCAFile != "")
		if *insecureHTTP {
			errCh <- srv.ListenAndServe()
			return
		}

		tlsCfg, err := buildTLSConfig(*tlsCertFile, *tlsKeyFile, *clientCAFile)
		if err != nil {
			errCh <- err
			return
		}
		srv.TLSConfig = tlsCfg
		errCh <- srv.ListenAndServeTLS("", "")
	}()

	select {
	case <-ctx.Done():
		log.Info("shutdown", "reason", ctx.Err())
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server error", "err", err)
			os.Exit(1)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}

func buildTLSConfig(certFile string, keyFile string, clientCAFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("missing --tls-cert-file/--tls-key-file")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
	}

	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}

	if clientCAFile != "" {
		caPEM, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read client ca file: %w", err)
		}
		pool := x509.NewCertPool()
		if ok := pool.AppendCertsFromPEM(caPEM); !ok {
			return nil, fmt.Errorf("parse client ca file")
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return cfg, nil
}

type multiValueFlag struct {
	values []string
}

func (m *multiValueFlag) String() string {
	if m == nil {
		return ""
	}
	return strings.Join(m.values, ",")
}

func (m *multiValueFlag) Set(v string) error {
	if m == nil {
		return fmt.Errorf("invalid flag receiver")
	}
	if strings.TrimSpace(v) == "" {
		return fmt.Errorf("flag value cannot be blank")
	}
	m.values = append(m.values, v)
	return nil
}

func (m *multiValueFlag) Values() []string {
	if m == nil {
		return nil
	}
	out := make([]string, len(m.values))
	copy(out, m.values)
	return out
}

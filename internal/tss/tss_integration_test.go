//go:build integration

package tss_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juno-intents/intents-juno/internal/tss"
	"github.com/juno-intents/intents-juno/internal/tsshost"
)

type countingSigner struct {
	calls atomic.Int64
	ret   []byte
}

func (s *countingSigner) Sign(_ context.Context, _ [32]byte, _ []byte) ([]byte, error) {
	s.calls.Add(1)
	return append([]byte(nil), s.ret...), nil
}

func TestClient_Integration_mTLSAndIdempotency(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	caCert, caKey := mustNewCA(t)
	serverCert := mustNewLeafCert(t, caCert, caKey, "server", []net.IP{net.ParseIP("127.0.0.1")})
	clientCert := mustNewLeafCert(t, caCert, caKey, "client", nil)

	signer := &countingSigner{ret: []byte("signed")}
	h := tsshost.NewHandler(signer, tsshost.Config{MaxBodyBytes: 1 << 20, MaxTxPlanBytes: 1 << 20, MaxSessions: 16, Now: time.Now})

	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    mustCertPool(t, caCert),
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	hc := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS13,
				RootCAs:      mustCertPool(t, caCert),
				Certificates: []tls.Certificate{clientCert},
			},
		},
	}

	c, err := tss.NewClient(srv.URL, tss.WithHTTPClient(hc))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	batchID := seq32(0x10)
	txPlan := []byte("plan-v1")

	got1, err := c.Sign(context.Background(), batchID, txPlan)
	if err != nil {
		t.Fatalf("Sign #1: %v", err)
	}
	got2, err := c.Sign(context.Background(), batchID, txPlan)
	if err != nil {
		t.Fatalf("Sign #2: %v", err)
	}
	if string(got1) != "signed" || string(got2) != "signed" {
		t.Fatalf("unexpected signed tx bytes")
	}
	if signer.calls.Load() != 1 {
		t.Fatalf("expected 1 signer call, got %d", signer.calls.Load())
	}
}

func seq32(start byte) (out [32]byte) {
	for i := 0; i < 32; i++ {
		out[i] = start + byte(i)
	}
	return out
}

func mustNewCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "test-ca",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert, key
}

func mustNewLeafCert(t *testing.T, ca *x509.Certificate, caKey *rsa.PrivateKey, cn string, ips []net.IP) tls.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		IPAddresses:  ips,
		DNSNames:     []string{cn},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return cert
}

func mustCertPool(t *testing.T, ca *x509.Certificate) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return pool
}

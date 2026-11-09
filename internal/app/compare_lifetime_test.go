package app

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"ipd/internal/config"
	"ipd/internal/lookup"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func r2BlockDNS(t *testing.T) {
	old := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("public DNS blocked in R2")
	}}
	t.Cleanup(func() { net.DefaultResolver = old })
}

func TestCompareFallbackTransportClosesIdle(t *testing.T) {
	if os.Getenv("IPD_COMPARE_LIFETIME_CHILD") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestCompareFallbackTransportClosesIdle$")
		cmd.Env = append(os.Environ(), "IPD_COMPARE_LIFETIME_CHILD=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated fixture: %v\n%s", err, out)
		}
		return
	}
	r2BlockDNS(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "R2 ephemeral test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, DNSNames: []string{"ipqualityscore.com", "api.abuseipdb.com"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	t.Setenv("GODEBUG", "x509usefallbackroots=1")
	x509.SetFallbackRoots(pool)
	cert, err := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(root, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", root)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var mu sync.Mutex
	var conns []net.Conn
	var accepted, requests, closed atomic.Int32
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			accepted.Add(1)
			go func() {
				defer func() { c.Close(); closed.Add(1) }()
				c.SetDeadline(time.Now().Add(15 * time.Second))
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				if req.Method != "CONNECT" {
					return
				}
				io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
				tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
				if tc.Handshake() != nil {
					return
				}
				br := bufio.NewReader(tc)
				for {
					req, err = http.ReadRequest(br)
					if err != nil {
						return
					}
					requests.Add(1)
					body := `{"success":true,"fraud_score":0}`
					if strings.Contains(req.Host, "abuseipdb") {
						body = `{"data":{"ipAddress":"1.1.1.1","abuseConfidenceScore":0}}`
					}
					fmt.Fprintf(tc, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
				}
			}()
		}
	}()
	s := &Service{Cfg: &config.Config{Proxy: "http://" + ln.Addr().String(), ProviderKeys: map[string]string{"ipqs": "R2_ONLY", "abuseipdb": "R2_ONLY"}}, Look: lookup.New()}
	for range 3 {
		rep, err := s.Compare(context.Background(), "1.1.1.1", true)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(rep)
		if strings.Contains(string(b), "provider_request_failed") {
			t.Fatalf("local tunnel did not serve both adapters: %s", b)
		}
	}
	if requests.Load() != 6 {
		t.Fatal("requests", requests.Load())
	}
	deadline := time.Now().Add(2 * time.Second)
	for accepted.Load() != closed.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if accepted.Load() != closed.Load() {
		t.Fatalf("3 calls opened %d connections, %d remain active; expected all fallback connections closed (fallback client remains nil=%v)", accepted.Load(), accepted.Load()-closed.Load(), s.comparisonClient == nil)
	}
}

package javakalkan

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skarm/kalkan/ckalkan"
)

func TestNetworkCallbackAndRecovery(t *testing.T) {
	var reject atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/ocsp-request" {
			t.Error("unexpected OCSP request headers")
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != "OCSP request" {
			t.Errorf("request body = %q", body)
		}
		if reject.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("authenticated by Java"))
	}))
	defer server.Close()
	t.Setenv("KALKAN_JAVA_TEST_URL", server.URL)
	c := testClient(t, "network")
	if err := c.Init(); err != nil {
		t.Fatal(err)
	}
	for _, failure := range []bool{false, true, false} {
		reject.Store(failure)
		result, err := c.HashData(ckalkan.SHA256, 0, nil)
		if failure {
			var remote *Error
			if !errors.As(err, &remote) || remote.Code != 3 || errors.Is(err, ErrWorkerFailed) {
				t.Fatalf("HTTP failure = %v; want recoverable validation failure", err)
			}
		} else if err != nil || string(result) != "authenticated by Java" {
			t.Fatalf("callback response = %q, %v", result, err)
		}
	}
}

func TestNetworkCallbackCancellation(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()
	t.Setenv("KALKAN_JAVA_TEST_URL", server.URL)
	c := testClient(t, "network")
	if err := c.Init(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c = c.WithContext(ctx)
	done := make(chan error, 1)
	go func() { _, err := c.HashData(ckalkan.SHA256, 0, nil); done <- err }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("network cancellation left the worker call blocked")
	}
}

func TestValidationFetchBoundaries(t *testing.T) {
	var reached atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Add(1)
		_, _ = w.Write([]byte("unwanted"))
	}))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	c := New(Config{MaxInputSize: 10}).WithContext(t.Context())
	if _, err := c.fetch(http.MethodGet, redirect.URL, nil); !errors.Is(err, errEndpoint) {
		t.Fatalf("redirect error = %v", err)
	}
	if reached.Load() != 0 {
		t.Fatal("redirect destination was contacted")
	}
	c.cfg.ValidateURL = func(string) (string, error) { return "", errors.New("forbidden") }
	if _, err := c.fetch(http.MethodGet, destination.URL, nil); !errors.Is(err, errEndpoint) || reached.Load() != 0 {
		t.Fatalf("endpoint policy error = %v, requests = %d", err, reached.Load())
	}
	c.cfg.ValidateURL = nil
	for _, endpoint := range []string{"file:///tmp/list.crl", "http://user:secret@example.com", "https://example.com/#fragment"} {
		if _, err := c.fetch(http.MethodGet, endpoint, nil); !errors.Is(err, errEndpoint) {
			t.Fatalf("unsafe endpoint accepted: %v", err)
		}
	}
	compressed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		writer := gzip.NewWriter(w)
		_, _ = writer.Write(bytes.Repeat([]byte("large response"), 1000))
		_ = writer.Close()
	}))
	defer compressed.Close()
	if _, err := c.fetch(http.MethodGet, compressed.URL, nil); !errors.Is(err, errEvidenceSize) {
		t.Fatalf("decompressed response limit = %v", err)
	}
}

func TestLocalCRLBundleLimit(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"issuer.crl", "root.der"} {
		if err := os.WriteFile(filepath.Join(dir, name), bytes.Repeat([]byte{1}, 100), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c := New(Config{MaxInputSize: 300}).WithContext(t.Context())
	if _, _, err := c.revocationSource("crl", dir); !errors.Is(err, errEvidenceSize) {
		t.Fatalf("combined CRL limit = %v", err)
	}
	c.cfg.MaxInputSize = 1024
	source, bundle, err := c.revocationSource("crl", dir)
	if err != nil || source != "" || bytes.Count(bundle, []byte("BEGIN X509 CRL")) != 2 {
		t.Fatalf("CRL bundle = %q, %v", bundle, err)
	}
}

func TestExplicitProxyRoutingAndPolicy(t *testing.T) {
	var requests atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.String() != "http://responder.invalid/status" {
			t.Errorf("unexpected destination %s", r.URL)
		}
		if r.Header.Get("Proxy-Authorization") != "Basic dXNlcjpwYXNz" {
			t.Error("proxy authentication missing")
		}
		if r.Header.Get("Content-Type") != "application/timestamp-query" {
			t.Error("TSP request headers missing")
		}
		_, _ = w.Write([]byte("timestamp response"))
	}))
	defer proxy.Close()
	host, port, err := net.SplitHostPort(strings.TrimPrefix(proxy.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	c := New(Config{}).WithContext(t.Context())
	if err := c.configureProxy(ckalkan.ProxyRequest{Flags: ckalkan.ProxyOn | ckalkan.ProxyAuth, Address: host, Port: port, User: "user", Password: "pass"}); err != nil {
		t.Fatal(err)
	}
	body, err := c.fetch("TSP", "http://responder.invalid/status", []byte("request"))
	if err != nil || string(body) != "timestamp response" || requests.Load() != 1 {
		t.Fatalf("proxy request: %q, %v, calls=%d", body, err, requests.Load())
	}
	c.cfg.ValidateURL = func(string) (string, error) { return "", errors.New("forbidden") }
	if _, err := c.fetch("TSP", "http://responder.invalid/status", nil); !errors.Is(err, errEndpoint) || requests.Load() != 1 {
		t.Fatal("proxy bypassed URL policy")
	}
	if err := c.configureProxy(ckalkan.ProxyRequest{}); err != nil || c.proxyURL != nil {
		t.Fatalf("proxy disable: %v", err)
	}
}

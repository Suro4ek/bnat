package server

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"testing"
)

func TestClientIP(t *testing.T) {
	trusted, err := ParseTrustedProxies("private, 203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: Config{TrustedProxies: trusted}}

	for _, tc := range []struct {
		name, remote, xff, want string
	}{
		{"direct client ignores spoofed header", "198.51.100.1:5000", "1.1.1.1", "198.51.100.1"},
		{"via docker proxy", "172.18.0.2:5000", "198.51.100.9", "198.51.100.9"},
		{"spoofed prefix is skipped", "172.18.0.2:5000", "6.6.6.6, 198.51.100.9", "198.51.100.9"},
		{"chain of trusted proxies", "127.0.0.1:5000", "198.51.100.9, 203.0.113.7, 10.0.0.5", "198.51.100.9"},
		{"proxy without header", "172.18.0.2:5000", "", "172.18.0.2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tc.remote
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got := s.clientIP(r); got != tc.want {
				t.Fatalf("clientIP = %q, want %q", got, tc.want)
			}
		})
	}

	if _, err := ParseTrustedProxies("not-an-ip"); err == nil {
		t.Fatal("bad proxy address accepted")
	}
}

func TestSetForwarded(t *testing.T) {
	trusted, _ := ParseTrustedProxies("private")
	s := &Server{cfg: Config{TrustedProxies: trusted}}

	forward := func(remote string, h http.Header) http.Header {
		in := httptest.NewRequest("GET", "http://app.bnat.example.com/", nil)
		in.RemoteAddr = remote
		in.Header = h
		pr := &httputil.ProxyRequest{In: in, Out: in.Clone(in.Context())}
		pr.Out.Header = http.Header{}
		s.setForwarded(pr)
		return pr.Out.Header
	}

	// Behind Traefik: keep https and the real client chain.
	out := forward("172.18.0.2:4000", http.Header{
		"X-Forwarded-For":   {"198.51.100.9"},
		"X-Forwarded-Proto": {"https"},
	})
	if out.Get("X-Forwarded-Proto") != "https" || out.Get("X-Forwarded-For") != "198.51.100.9, 172.18.0.2" {
		t.Fatalf("trusted proxy headers not preserved: %v", out)
	}

	// Direct client: its own claims are dropped.
	out = forward("198.51.100.1:4000", http.Header{
		"X-Forwarded-For":   {"6.6.6.6"},
		"X-Forwarded-Proto": {"https"},
	})
	if out.Get("X-Forwarded-Proto") != "http" || out.Get("X-Forwarded-For") != "198.51.100.1" {
		t.Fatalf("untrusted client headers were trusted: %v", out)
	}
}

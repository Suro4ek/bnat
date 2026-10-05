package server

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"strings"
)

// ParseTrustedProxies parses a comma-separated list of IPs/CIDRs. The keyword
// "private" expands to loopback and private ranges (typical for a reverse
// proxy on the same host or docker network).
func ParseTrustedProxies(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		if f == "private" {
			for _, p := range []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7"} {
				out = append(out, netip.MustParsePrefix(p))
			}
			continue
		}
		if !strings.Contains(f, "/") {
			a, err := netip.ParseAddr(f)
			if err != nil {
				return nil, fmt.Errorf("trusted proxy %q: %v", f, err)
			}
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(f)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q: %v", f, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func (s *Server) trusted(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range s.cfg.TrustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// fromProxy reports whether the request came through a trusted reverse proxy.
func (s *Server) fromProxy(r *http.Request) bool {
	return s.trusted(remoteHost(r))
}

// clientIP returns the real client address: for requests from trusted proxies
// it is the right-most untrusted entry of X-Forwarded-For.
func (s *Server) clientIP(r *http.Request) string {
	ip := remoteHost(r)
	if !s.trusted(ip) {
		return ip
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		h := strings.TrimSpace(hops[i])
		if h == "" {
			continue
		}
		if !s.trusted(h) {
			return h
		}
		ip = h
	}
	return ip
}

// setForwarded sets X-Forwarded-* on a proxied request, keeping the values a
// trusted front proxy already established (client chain, https, public host).
func (s *Server) setForwarded(pr *httputil.ProxyRequest) {
	if !s.fromProxy(pr.In) {
		pr.SetXForwarded()
		return
	}
	in := pr.In.Header
	xff := remoteHost(pr.In)
	if prior := in.Values("X-Forwarded-For"); len(prior) > 0 {
		xff = strings.Join(prior, ", ") + ", " + xff
	}
	pr.Out.Header.Set("X-Forwarded-For", xff)
	host := in.Get("X-Forwarded-Host")
	if host == "" {
		host = pr.In.Host
	}
	pr.Out.Header.Set("X-Forwarded-Host", host)
	proto := in.Get("X-Forwarded-Proto")
	if proto == "" {
		proto = "http"
	}
	pr.Out.Header.Set("X-Forwarded-Proto", proto)
}

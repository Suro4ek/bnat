package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Suro4ek/bnat/internal/client"
	"github.com/Suro4ek/bnat/internal/proto"
)

// TestEndToEnd runs a server and an agent in-process and exercises pairing,
// tcp, http and built-in ssh tunnels.
func TestEndToEnd(t *testing.T) {
	s, err := New(Config{
		Domain:        "127.0.0.1",
		HTTPAddr:      ":0",
		DataDir:       t.TempDir(),
		AdminPassword: "test",
		TCPBind:       "127.0.0.1",
		PortMin:       30000,
		PortMax:       39999,
	})
	if err != nil {
		t.Fatal(err)
	}
	drainOnCleanup(t, s)
	ts := httptest.NewServer(s)
	defer ts.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Pairing: code works once, case-insensitively.
	code, err := s.store.CreateClient("ci")
	if err != nil {
		t.Fatal(err)
	}
	paired, err := client.Pair(ctx, ts.URL, strings.ToLower(code))
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	if _, err := client.Pair(ctx, ts.URL, code); err == nil {
		t.Fatal("pairing code was accepted twice")
	}

	// Local services behind "NAT".
	echo := listenEcho(t)
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello %s via %s", r.URL.Path, r.Header.Get("X-Forwarded-Host"))
	}))
	defer web.Close()

	tunnels := []client.Tunnel{
		{Req: proto.TunnelReq{Name: "echo", Type: proto.TypeTCP}, Handler: client.ForwardHandler{Addr: echo}},
		{Req: proto.TunnelReq{Name: "web", Type: proto.TypeHTTP}, Handler: client.ForwardHandler{Addr: web.Listener.Addr().String()}},
	}
	if runtime.GOOS != "windows" {
		sshd, err := client.NewSSHServer(filepath.Join(t.TempDir(), "host_key"), "/bin/sh")
		if err != nil {
			t.Fatal(err)
		}
		tunnels = append(tunnels, client.Tunnel{Req: proto.TunnelReq{Name: "box", Type: proto.TypeSSH, Embedded: true}, Handler: sshd})
	}
	agent := &client.Client{Config: client.Config{Server: ts.URL, Token: paired.Token}, Tunnels: tunnels}
	agentDone := make(chan error, 1)
	go func() { agentDone <- agent.Run(ctx) }()

	waitFor(t, "tunnels to come up", func() bool {
		s.mu.RLock()
		defer s.mu.RUnlock()
		return len(s.tunnels) == len(tunnels)
	})

	t.Run("tcp", func(t *testing.T) {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", s.tunnelPort("echo")))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		fmt.Fprint(c, "ping")
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
			t.Fatalf("echo got %q, %v", buf, err)
		}
	})

	t.Run("http", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL+"/path", nil)
		req.Host = "web.127.0.0.1"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if want := "hello /path via web.127.0.0.1"; string(body) != want {
			t.Fatalf("got %d %q, want %q", resp.StatusCode, body, want)
		}

		req.Host = "missing.127.0.0.1"
		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("offline tunnel: got %d, want 502", resp.StatusCode)
		}
	})

	t.Run("ssh", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("built-in sshd needs a unix shell")
		}
		addr := fmt.Sprintf("127.0.0.1:%d", s.tunnelPort("box"))
		good, goodPub := newSSHKey(t)
		bad, _ := newSSHKey(t)

		if err := s.store.AddKey("ci", string(ssh.MarshalAuthorizedKey(goodPub)), []string{"box"}); err != nil {
			t.Fatal(err)
		}
		s.pushKeys()

		var out string
		waitFor(t, "authorized key to reach the agent", func() bool {
			out, err = sshRun(addr, good, "echo hi; exit 0")
			return err == nil
		})
		if out != "hi\n" {
			t.Fatalf("ssh output %q", out)
		}
		if _, err := sshRun(addr, bad, "true"); err == nil {
			t.Fatal("unauthorized key was accepted")
		}
		if _, err := sshRun(addr, good, "exit 3"); err == nil || !strings.Contains(err.Error(), "status 3") {
			t.Fatalf("want exit status 3, got %v", err)
		}
	})

	t.Run("revoked client is dropped", func(t *testing.T) {
		s.kickToken(s.store.Tokens()[0].ID)
		s.store.DeleteToken(s.store.Tokens()[0].ID)
		select {
		case err := <-agentDone:
			if err == nil || !strings.Contains(err.Error(), "rejected") {
				t.Fatalf("agent exited with %v, want token rejection", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("agent did not stop after its client was removed")
		}
	})
}

// drainOnCleanup waits for agent sessions to finish before the test's TempDir
// is removed (cleanups run in reverse order, after the test's defers).
func drainOnCleanup(t *testing.T, s *Server) {
	t.Cleanup(func() {
		waitFor(t, "agent sessions to close", func() bool {
			s.mu.RLock()
			defer s.mu.RUnlock()
			return len(s.sessions) == 0
		})
	})
}

func (s *Server) tunnelPort(name string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tunnels[name].port
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func listenEcho(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return ln.Addr().String()
}

func newSSHKey(t *testing.T) (ssh.Signer, ssh.PublicKey) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer, signer.PublicKey()
}

func sshRun(addr string, key ssh.Signer, cmd string) (string, error) {
	c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "ci",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(key)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		return "", err
	}
	defer c.Close()
	sess, err := c.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	out, err := sess.Output(cmd)
	return string(out), err
}

// Agents may reach the server by an internal name (docker service, IP), while
// other paths on unknown hosts stay 404.
func TestAgentAPIOnAnyHost(t *testing.T) {
	s, err := New(Config{Domain: "bnat.example.com", HTTPAddr: ":0", DataDir: t.TempDir(), AdminPassword: "x", PortMin: 1, PortMax: 2})
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]int{proto.PairPath: http.StatusForbidden, "/": http.StatusNotFound} {
		req := httptest.NewRequest("POST", "http://bnat:8080"+path, strings.NewReader(`{"code":"NOPE-NOPE"}`))
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("POST %s on unknown host: got %d, want %d", path, rec.Code, want)
		}
	}
}

// TestReconnectTakeover: an agent that comes back while the server still holds
// its old, dead connection takes the tunnel over at once; a live holder keeps it.
func TestReconnectTakeover(t *testing.T) {
	s, err := New(Config{Domain: "127.0.0.1", HTTPAddr: ":0", DataDir: t.TempDir(), AdminPassword: "x", TCPBind: "127.0.0.1", PortMin: 40000, PortMax: 49999})
	if err != nil {
		t.Fatal(err)
	}
	drainOnCleanup(t, s)
	ts := httptest.NewServer(s)
	defer ts.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	code, _ := s.store.CreateClient("ci")
	paired, err := client.Pair(ctx, ts.URL, code)
	if err != nil {
		t.Fatal(err)
	}
	echo := listenEcho(t)
	startAgent := func(server string) context.CancelFunc {
		actx, acancel := context.WithCancel(ctx)
		a := &client.Client{
			Config:  client.Config{Server: server, Token: paired.Token},
			Tunnels: []client.Tunnel{{Req: proto.TunnelReq{Name: "box", Type: proto.TypeTCP}, Handler: client.ForwardHandler{Addr: echo}}},
		}
		go a.Run(actx)
		return acancel
	}
	holder := func() *agentSession {
		s.mu.RLock()
		defer s.mu.RUnlock()
		if t := s.tunnels["box"]; t != nil {
			return t.sess
		}
		return nil
	}

	// First agent goes through a proxy we can freeze, like a link that died
	// without the server being told.
	proxy := newFreezeProxy(t, ts.Listener.Addr().String())
	stop1 := startAgent("http://" + proxy.addr)
	defer stop1()
	waitFor(t, "first agent", func() bool { return holder() != nil })
	first := holder()

	// A second live agent must not steal the tunnel.
	stop2 := startAgent(ts.URL)
	time.Sleep(2 * time.Second)
	if holder() != first {
		t.Fatal("tunnel was taken from a live agent")
	}
	stop2()

	// Freeze the first agent's link; a new agent takes over within the ping timeout.
	proxy.freeze()
	start := time.Now()
	stop3 := startAgent(ts.URL)
	defer stop3()
	deadline := time.Now().Add(stalePingTimeout + 10*time.Second)
	for h := holder(); h == nil || h == first; h = holder() {
		if time.Now().After(deadline) {
			t.Fatal("dead agent was not replaced")
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("took over after %s", time.Since(start).Round(100*time.Millisecond))

	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", s.tunnelPort("box")))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprint(c, "ping")
	buf := make([]byte, 4)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("tunnel after takeover: %q, %v", buf, err)
	}
}

// freezeProxy forwards TCP until frozen; then it keeps the connections open
// but stops passing data, so pings go unanswered.
type freezeProxy struct {
	addr   string
	frozen atomic.Bool
}

func newFreezeProxy(t *testing.T, target string) *freezeProxy {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	p := &freezeProxy{addr: ln.Addr().String()}
	pipe := func(dst, src net.Conn) {
		buf := make([]byte, 32<<10)
		for {
			n, err := src.Read(buf)
			for p.frozen.Load() {
				time.Sleep(10 * time.Millisecond)
			}
			if n > 0 {
				dst.Write(buf[:n])
			}
			if err != nil {
				dst.Close()
				return
			}
		}
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			u, err := net.Dial("tcp", target)
			if err != nil {
				c.Close()
				continue
			}
			go pipe(u, c)
			go pipe(c, u)
		}
	}()
	return p
}

func (p *freezeProxy) freeze() { p.frozen.Store(true) }

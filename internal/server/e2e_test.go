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

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"

	"github.com/Suro4ek/bnat/internal/proto"
)

// Handler serves one public connection delivered through the tunnel.
type Handler interface {
	Serve(c net.Conn, remote string)
}

// KeyReceiver is implemented by handlers that need authorized keys.
type KeyReceiver interface {
	SetKeys(lines []string)
}

// ForwardHandler pipes connections to a local TCP address.
type ForwardHandler struct{ Addr string }

func (f ForwardHandler) Serve(c net.Conn, remote string) {
	l, err := net.DialTimeout("tcp", f.Addr, 10*time.Second)
	if err != nil {
		slog.Warn("dial local", "addr", f.Addr, "err", err)
		c.Close()
		return
	}
	proto.Join(c, l)
}

type Tunnel struct {
	Req     proto.TunnelReq
	Handler Handler
}

type Client struct {
	Config  Config
	Tunnels []Tunnel
	Log     *slog.Logger
}

var errFatal = errors.New("fatal")

// maxBackoff caps the pause between reconnect attempts, so a tunnel comes back
// at most ~15s after the network does.
const maxBackoff = 15 * time.Second

// Run connects to the server and reconnects until ctx is cancelled or the
// server rejects us permanently (bad token).
func (c *Client) Run(ctx context.Context) error {
	if c.Log == nil {
		c.Log = slog.Default()
	}
	backoff := time.Second
	for {
		start := time.Now()
		err := c.session(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, errFatal) {
			return err
		}
		if time.Since(start) > time.Minute {
			backoff = time.Second
		}
		// ±20% jitter so agents don't reconnect in lockstep after a server restart.
		wait := backoff + time.Duration((rand.Float64()*0.4-0.2)*float64(backoff))
		c.Log.Warn("disconnected, reconnecting", "err", err, "in", wait.Round(100*time.Millisecond))
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return nil
		}
		backoff = min(backoff*2, maxBackoff)
	}
}

func agentURL(server string) (string, error) {
	u, err := url.Parse(server)
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "https", "wss":
		u.Scheme = "wss"
	case "http", "ws":
		u.Scheme = "ws"
	default:
		return "", fmt.Errorf("server URL must start with https:// or http://, got %q", server)
	}
	u.Path = proto.AgentPath
	return u.String(), nil
}

func (c *Client) session(ctx context.Context) error {
	wsURL, err := agentURL(c.Config.Server)
	if err != nil {
		return fmt.Errorf("%w: %v", errFatal, err)
	}
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	wc, resp, err := websocket.Dial(dctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": {"Bearer " + c.Config.Token}},
	})
	cancel()
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			return fmt.Errorf("%w: server rejected the token", errFatal)
		}
		return err
	}
	nc := websocket.NetConn(context.Background(), wc, websocket.MessageBinary)
	mux, err := yamux.Client(nc, proto.YamuxConfig())
	if err != nil {
		nc.Close()
		return err
	}
	defer mux.Close()
	go func() {
		select {
		case <-ctx.Done():
			mux.Close()
		case <-mux.CloseChan():
		}
	}()

	ctrl, err := mux.OpenStream()
	if err != nil {
		return err
	}
	hello := proto.Hello{Version: proto.Version, Hostname: hostname(), User: username()}
	for _, t := range c.Tunnels {
		hello.Tunnels = append(hello.Tunnels, t.Req)
	}
	if err := json.NewEncoder(ctrl).Encode(hello); err != nil {
		return err
	}
	dec := json.NewDecoder(ctrl)
	var welcome proto.ServerMsg
	if err := dec.Decode(&welcome); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}

	handlers := map[string]Handler{}
	var failed []string
	for i, info := range welcome.Tunnels {
		if info.Error != "" {
			failed = append(failed, info.Error)
			continue
		}
		if i < len(c.Tunnels) {
			handlers[info.Name] = c.Tunnels[i].Handler
			printTunnel(info, c.Tunnels[i].Req)
		}
	}
	if len(handlers) == 0 {
		return fmt.Errorf("no tunnels accepted: %s", strings.Join(failed, "; "))
	}
	for _, f := range failed {
		c.Log.Warn("tunnel rejected", "err", f)
	}

	go func() {
		for {
			var m proto.ServerMsg
			if err := dec.Decode(&m); err != nil {
				mux.Close()
				return
			}
			if m.Type == proto.MsgKeys {
				for name, lines := range m.Keys {
					if kr, ok := handlers[name].(KeyReceiver); ok {
						kr.SetKeys(lines)
					}
				}
			}
		}
	}()

	for {
		st, err := mux.AcceptStream()
		if err != nil {
			return err
		}
		go func() {
			st.SetReadDeadline(time.Now().Add(15 * time.Second))
			h, err := proto.ReadHeader(st)
			st.SetReadDeadline(time.Time{})
			if err != nil {
				st.Close()
				return
			}
			handler := handlers[h.Tunnel]
			if handler == nil {
				st.Close()
				return
			}
			handler.Serve(st, h.Remote)
		}()
	}
}

func printTunnel(info proto.TunnelInfo, req proto.TunnelReq) {
	switch info.Type {
	case proto.TypeHTTP:
		fmt.Fprintf(os.Stderr, "\n  %s  →  %s\n\n", info.URL, req.Local)
	case proto.TypeSSH:
		fmt.Fprintf(os.Stderr, "\n  ssh tunnel %q is up\n\n    ssh -p %d %s@%s\n\n", info.Name, info.Port, username(), info.Host)
	default:
		fmt.Fprintf(os.Stderr, "\n  tcp://%s:%d  →  %s\n\n", info.Host, info.Port, req.Local)
	}
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}

func username() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return os.Getenv("USER")
}

// Pair redeems a pairing code from the admin panel and returns the token.
func Pair(ctx context.Context, server, code string) (proto.PairResponse, error) {
	var resp proto.PairResponse
	u, err := url.Parse(server)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return resp, fmt.Errorf("server must look like https://bnat.example.com, got %q", server)
	}
	u.Path = proto.PairPath
	body, _ := json.Marshal(proto.PairRequest{Code: code, Hostname: hostname(), User: username()})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return resp, err
	}
	req.Header.Set("Content-Type", "application/json")
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		return resp, err
	}
	defer r.Body.Close()
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&resp); err != nil {
		return resp, fmt.Errorf("unexpected response from server (HTTP %d)", r.StatusCode)
	}
	if resp.Error != "" {
		return resp, errors.New(resp.Error)
	}
	if resp.Token == "" {
		return resp, fmt.Errorf("server returned no token (HTTP %d)", r.StatusCode)
	}
	return resp, nil
}

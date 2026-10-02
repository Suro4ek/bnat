// Package proto holds the wire protocol shared by the bnat server and agent.
//
// The agent opens a WebSocket to AgentPath and runs a yamux session over it.
// The first stream (opened by the agent) is the control stream carrying
// newline-delimited JSON: one Hello from the agent, then ServerMsg values from
// the server. Every public connection is delivered as a new stream opened by
// the server, prefixed with a length-delimited StreamHeader.
package proto

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
)

const (
	AgentPath = "/_bnat/agent"
	PairPath  = "/_bnat/pair"
	Version   = 1
)

// PairRequest redeems a pairing code from the admin panel for a token.
type PairRequest struct {
	Code     string `json:"code"`
	Hostname string `json:"hostname"`
	User     string `json:"user"`
}

type PairResponse struct {
	Token string `json:"token,omitempty"`
	Name  string `json:"name,omitempty"`
	Error string `json:"error,omitempty"`
}

const (
	TypeSSH  = "ssh"
	TypeHTTP = "http"
	TypeTCP  = "tcp"
)

var nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidName reports whether name can be used as a tunnel name / DNS label.
func ValidName(name string) bool { return nameRe.MatchString(name) }

type TunnelReq struct {
	Name string `json:"name"`
	Type string `json:"type"`
	// Embedded means the agent runs the built-in SSH server and needs the
	// authorized keys configured in the admin panel.
	Embedded bool `json:"embedded,omitempty"`
	// HostHeader, when set, replaces the Host header of proxied HTTP requests.
	HostHeader string `json:"host_header,omitempty"`
	// Local is informational: what the agent forwards to.
	Local string `json:"local,omitempty"`
}

type Hello struct {
	Version  int         `json:"version"`
	Hostname string      `json:"hostname"`
	User     string      `json:"user"`
	Tunnels  []TunnelReq `json:"tunnels"`
}

type TunnelInfo struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	URL   string `json:"url,omitempty"`  // http tunnels
	Host  string `json:"host,omitempty"` // tcp/ssh tunnels
	Port  int    `json:"port,omitempty"`
	Error string `json:"error,omitempty"`
}

const (
	MsgWelcome = "welcome"
	MsgKeys    = "keys"
)

type ServerMsg struct {
	Type    string       `json:"type"`
	Tunnels []TunnelInfo `json:"tunnels,omitempty"`
	// Keys maps tunnel name to authorized_keys lines.
	Keys map[string][]string `json:"keys,omitempty"`
}

type StreamHeader struct {
	Tunnel string `json:"tunnel"`
	Remote string `json:"remote,omitempty"`
}

func WriteHeader(w io.Writer, h StreamHeader) error {
	b, err := json.Marshal(h)
	if err != nil {
		return err
	}
	buf := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(buf, uint16(len(b)))
	copy(buf[2:], b)
	_, err = w.Write(buf)
	return err
}

func ReadHeader(r io.Reader) (StreamHeader, error) {
	var h StreamHeader
	var lb [2]byte
	if _, err := io.ReadFull(r, lb[:]); err != nil {
		return h, err
	}
	n := binary.BigEndian.Uint16(lb[:])
	if n == 0 {
		return h, errors.New("empty stream header")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return h, err
	}
	return h, json.Unmarshal(b, &h)
}

func YamuxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	c.KeepAliveInterval = 20 * time.Second
	c.ConnectionWriteTimeout = 30 * time.Second
	c.MaxStreamWindowSize = 4 << 20
	c.LogOutput = io.Discard
	return c
}

// Join copies data in both directions until both sides are done, half-closing
// where possible. It returns bytes copied a->b and b->a.
func Join(a, b io.ReadWriteCloser) (ab, ba int64) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src io.ReadWriteCloser, n *int64) {
		defer wg.Done()
		*n, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
	}
	go cp(b, a, &ab)
	go cp(a, b, &ba)
	wg.Wait()
	a.Close()
	b.Close()
	return
}

// CountingConn counts bytes read and written into the given counters.
type CountingConn struct {
	net.Conn
	In, Out *atomic.Int64
}

func (c *CountingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.In.Add(int64(n))
	return n, err
}

func (c *CountingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.Out.Add(int64(n))
	return n, err
}

func (c *CountingConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

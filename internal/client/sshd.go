package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/creack/pty"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/suro/bnat/internal/proto"
)

// SSHServer is a minimal SSH server running inside the agent. Users are
// authenticated against keys pushed from the bnat admin panel; sessions run
// as the user that started the agent.
type SSHServer struct {
	Shell string
	Log   *slog.Logger

	cfg  *ssh.ServerConfig
	keys atomic.Pointer[map[string]string] // marshaled key -> fingerprint
}

func NewSSHServer(hostKeyPath, shell string) (*SSHServer, error) {
	signer, err := loadHostKey(hostKeyPath)
	if err != nil {
		return nil, fmt.Errorf("host key: %w", err)
	}
	if shell == "" {
		shell = os.Getenv("SHELL")
	}
	if shell == "" {
		shell = "/bin/sh"
	}
	s := &SSHServer{Shell: shell, Log: slog.Default()}
	s.cfg = &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if m := s.keys.Load(); m != nil {
				if fp, ok := (*m)[string(key.Marshal())]; ok {
					return &ssh.Permissions{Extensions: map[string]string{"fp": fp}}, nil
				}
			}
			return nil, errors.New("key not authorized")
		},
		ServerVersion: "SSH-2.0-bnat",
	}
	s.cfg.AddHostKey(signer)
	return s, nil
}

func loadHostKey(path string) (ssh.Signer, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		blk, err := ssh.MarshalPrivateKey(priv, "bnat host key")
		if err != nil {
			return nil, err
		}
		b = pem.EncodeToMemory(blk)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, b, 0o600); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(b)
}

func (s *SSHServer) SetKeys(lines []string) {
	m := map[string]string{}
	for _, l := range lines {
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(l))
		if err != nil {
			continue
		}
		m[string(pk.Marshal())] = ssh.FingerprintSHA256(pk)
	}
	s.keys.Store(&m)
	s.Log.Info("authorized keys updated", "count", len(m))
}

func (s *SSHServer) Serve(c net.Conn, remote string) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	sc, chans, reqs, err := ssh.NewServerConn(c, s.cfg)
	if err != nil {
		s.Log.Info("ssh handshake failed", "remote", remote, "err", err)
		return
	}
	defer sc.Close()
	c.SetDeadline(time.Time{})
	log := s.Log.With("remote", remote, "user", sc.User(), "key", sc.Permissions.Extensions["fp"])
	log.Info("ssh login")
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		switch nc.ChannelType() {
		case "session":
			go s.session(nc, log)
		case "direct-tcpip":
			go s.directTCPIP(nc)
		default:
			nc.Reject(ssh.UnknownChannelType, "unsupported channel type")
		}
	}
	log.Info("ssh logout")
}

type ptyRequest struct {
	Term          string
	Columns, Rows uint32
	Width, Height uint32
	Modes         string
}

func (s *SSHServer) session(nc ssh.NewChannel, log *slog.Logger) {
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	defer ch.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // kills the process if the client goes away

	var (
		mu      sync.Mutex
		ptmx    *os.File
		ptyReq  *ptyRequest
		env     []string
		started bool
	)
	setPty := func(f *os.File) {
		mu.Lock()
		ptmx = f
		mu.Unlock()
	}

	for req := range reqs {
		ok := false
		var start func() int
		switch req.Type {
		case "pty-req":
			var p ptyRequest
			if ssh.Unmarshal(req.Payload, &p) == nil {
				ptyReq, ok = &p, true
			}
		case "env":
			var e struct{ Name, Value string }
			if ssh.Unmarshal(req.Payload, &e) == nil {
				env, ok = append(env, e.Name+"="+e.Value), true
			}
		case "window-change":
			var w struct{ Columns, Rows, Width, Height uint32 }
			if ssh.Unmarshal(req.Payload, &w) == nil {
				mu.Lock()
				if ptmx != nil {
					pty.Setsize(ptmx, &pty.Winsize{Rows: uint16(w.Rows), Cols: uint16(w.Columns)})
				} else if ptyReq != nil {
					ptyReq.Columns, ptyReq.Rows = w.Columns, w.Rows
				}
				mu.Unlock()
				ok = true
			}
		case "shell":
			if !started {
				p, e := ptyReq, env
				start = func() int { return s.run(ctx, ch, "", p, e, setPty) }
			}
		case "exec":
			var x struct{ Command string }
			if !started && ssh.Unmarshal(req.Payload, &x) == nil {
				p, e := ptyReq, env
				log.Info("ssh exec", "cmd", x.Command)
				start = func() int { return s.run(ctx, ch, x.Command, p, e, setPty) }
			}
		case "subsystem":
			var x struct{ Name string }
			if !started && ssh.Unmarshal(req.Payload, &x) == nil && x.Name == "sftp" {
				start = func() int { return serveSFTP(ch) }
			}
		}
		if start != nil {
			started, ok = true, true
		}
		if req.WantReply {
			req.Reply(ok, nil)
		}
		if start != nil {
			go func() {
				code := start()
				ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(code)}))
				ch.Close()
			}()
		}
	}
}

func (s *SSHServer) run(ctx context.Context, ch ssh.Channel, command string, p *ptyRequest, env []string, setPty func(*os.File)) int {
	var cmd *exec.Cmd
	if command == "" {
		cmd = exec.CommandContext(ctx, s.Shell, "-l")
	} else {
		cmd = exec.CommandContext(ctx, s.Shell, "-c", command)
	}
	cmd.Dir, _ = os.UserHomeDir()
	cmd.Env = append(os.Environ(), env...)

	if p != nil {
		cmd.Env = append(cmd.Env, "TERM="+p.Term)
		f, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: uint16(p.Rows), Cols: uint16(p.Columns)})
		if err != nil {
			fmt.Fprintf(ch.Stderr(), "bnat: start shell: %v\r\n", err)
			return 1
		}
		setPty(f)
		go io.Copy(f, ch)
		io.Copy(ch, f)
		setPty(nil)
		f.Close()
		return exitCode(cmd.Wait())
	}

	cmd.Stdout, cmd.Stderr = ch, ch.Stderr()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return 1
	}
	go func() {
		io.Copy(stdin, ch)
		stdin.Close()
	}()
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(ch.Stderr(), "bnat: %v\n", err)
		return 127
	}
	return exitCode(cmd.Wait())
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() >= 0 {
		return ee.ExitCode()
	}
	return 255
}

func serveSFTP(ch ssh.Channel) int {
	home, _ := os.UserHomeDir()
	srv, err := sftp.NewServer(ch, sftp.WithServerWorkingDirectory(home))
	if err != nil {
		return 1
	}
	if err := srv.Serve(); err != nil && err != io.EOF {
		return 1
	}
	return 0
}

func (s *SSHServer) directTCPIP(nc ssh.NewChannel) {
	var p struct {
		DestAddr string
		DestPort uint32
		OrigAddr string
		OrigPort uint32
	}
	if err := ssh.Unmarshal(nc.ExtraData(), &p); err != nil {
		nc.Reject(ssh.ConnectionFailed, "bad request")
		return
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(p.DestAddr, strconv.Itoa(int(p.DestPort))), 10*time.Second)
	if err != nil {
		nc.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		conn.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	proto.Join(ch, conn)
}

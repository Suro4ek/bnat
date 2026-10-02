package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Suro4ek/bnat/internal/client"
	"github.com/Suro4ek/bnat/internal/proto"
	"github.com/Suro4ek/bnat/internal/server"
)

var version = "dev"

const usage = `bnat — expose services behind NAT

Agent (machine behind NAT):
  bnat login https://bnat.example.com <CODE>   code from admin panel → Clients
  bnat ssh  [-n name] [--local 127.0.0.1:22]   SSH access (built-in sshd, keys from admin panel)
  bnat http [-n name] [--host-header rewrite] <port|addr>
  bnat tcp  [-n name] <port|addr>

Server (public VPS):
  bnat server --domain bnat.example.com [--tcp-host tun.bnat.example.com] [flags]

Run "bnat <command> -h" for command flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "server":
		err = runServer(args)
	case "login":
		err = runLogin(args)
	case "ssh", "http", "tcp":
		err = runTunnel(cmd, args)
	case "version", "--version":
		fmt.Println("bnat", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "bnat:", err)
		os.Exit(1)
	}
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil {
		return v
	}
	return def
}

func runServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	var c server.Config
	var ports string
	fs.StringVar(&c.Domain, "domain", env("BNAT_DOMAIN", ""), "main domain: admin panel and *.domain HTTP tunnels (env BNAT_DOMAIN)")
	fs.StringVar(&c.TCPHost, "tcp-host", env("BNAT_TCP_HOST", ""), "hostname shown for ssh/tcp tunnels, defaults to --domain (env BNAT_TCP_HOST)")
	fs.BoolVar(&c.TLS, "tls", env("BNAT_TLS", "true") == "true", "obtain Let's Encrypt certificates and serve HTTPS (env BNAT_TLS)")
	fs.StringVar(&c.HTTPAddr, "http", env("BNAT_HTTP", ":80"), "plain HTTP listen address (env BNAT_HTTP)")
	fs.StringVar(&c.HTTPSAddr, "https", env("BNAT_HTTPS", ":443"), "HTTPS listen address when --tls (env BNAT_HTTPS)")
	fs.StringVar(&c.ACMEEmail, "acme-email", env("BNAT_ACME_EMAIL", ""), "contact email for Let's Encrypt (env BNAT_ACME_EMAIL)")
	fs.StringVar(&c.PublicScheme, "public-scheme", env("BNAT_PUBLIC_SCHEME", ""), "scheme for printed URLs; set to https when TLS is terminated by a proxy in front")
	fs.StringVar(&c.DataDir, "data", env("BNAT_DATA", "./data"), "data directory (env BNAT_DATA)")
	fs.StringVar(&c.AdminPassword, "admin-password", env("BNAT_ADMIN_PASSWORD", ""), "admin password; generated on first start if empty (env BNAT_ADMIN_PASSWORD)")
	fs.StringVar(&c.TCPBind, "tcp-bind", env("BNAT_TCP_BIND", ""), "address tcp/ssh tunnel ports bind to (env BNAT_TCP_BIND)")
	fs.StringVar(&ports, "ports", env("BNAT_PORTS", "20000-29999"), "port range for tcp/ssh tunnels (env BNAT_PORTS)")
	debug := fs.Bool("debug", false, "verbose logging")
	fs.Parse(args)

	lo, hi, ok := strings.Cut(ports, "-")
	c.PortMin, _ = strconv.Atoi(lo)
	c.PortMax, _ = strconv.Atoi(hi)
	if !ok || c.PortMin <= 0 || c.PortMax > 65535 {
		return fmt.Errorf("bad --ports %q, want e.g. 20000-29999", ports)
	}
	setupLog(*debug)

	s, err := server.New(c)
	if err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()
	return s.Run(ctx)
}

func runLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	srv := fs.String("server", "", "server URL, e.g. https://bnat.example.com")
	tok := fs.String("token", "", "use an existing token instead of a pairing code")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: bnat login https://bnat.example.com <CODE>")
		fmt.Fprintln(os.Stderr, "       (create a client in the admin panel → Clients to get a code)")
		fs.PrintDefaults()
	}
	fs.Parse(reorder(args))
	code := ""
	switch fs.NArg() {
	case 2:
		*srv, code = fs.Arg(0), fs.Arg(1)
	case 1:
		code = fs.Arg(0)
	}
	if *srv != "" && !strings.Contains(*srv, "://") {
		*srv = "https://" + *srv
	}
	*srv = strings.TrimRight(*srv, "/")
	if *srv == "" || (code == "" && *tok == "") {
		fs.Usage()
		os.Exit(2)
	}

	cfg := client.Config{Server: *srv, Token: *tok}
	if code != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		resp, err := client.Pair(ctx, *srv, code)
		if err != nil {
			return fmt.Errorf("pairing failed: %w", err)
		}
		cfg.Token = resp.Token
		fmt.Printf("paired as client %q\n", resp.Name)
	}
	p, err := client.SaveConfig(cfg)
	if err != nil {
		return err
	}
	fmt.Println("saved", p)
	return nil
}

// parseLocal turns "3000", ":3000" or "host:3000" into a dialable address.
func parseLocal(s string) (string, error) {
	if _, err := strconv.Atoi(s); err == nil {
		return "127.0.0.1:" + s, nil
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", fmt.Errorf("bad local address %q", s)
	}
	if host == "" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port), nil
}

func runTunnel(typ string, args []string) error {
	fs := flag.NewFlagSet(typ, flag.ExitOnError)
	name := fs.String("n", "", "tunnel name (subdomain for http); random if empty")
	fs.StringVar(name, "name", "", "same as -n")
	var local, shell, hostHeader *string
	switch typ {
	case proto.TypeSSH:
		local = fs.String("local", "", "forward to an existing sshd (e.g. 127.0.0.1:22) instead of the built-in one")
		shell = fs.String("shell", "", "shell for the built-in sshd (default $SHELL)")
	case proto.TypeHTTP:
		hostHeader = fs.String("host-header", "", `Host header sent to the local service: "rewrite" = local address, or a literal value; default keeps the public host`)
	}
	debug := fs.Bool("debug", false, "verbose logging")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: bnat %s [flags]", typ)
		if typ != proto.TypeSSH {
			fmt.Fprint(os.Stderr, " <port|addr>")
		}
		fmt.Fprintln(os.Stderr)
		fs.PrintDefaults()
	}
	fs.Parse(reorder(args))
	setupLog(*debug)

	cfg, err := client.LoadConfig()
	if err != nil {
		return err
	}
	req := proto.TunnelReq{Name: strings.ToLower(*name), Type: typ}
	if req.Name != "" && !proto.ValidName(req.Name) {
		return fmt.Errorf("invalid name %q: use a-z, 0-9 and '-'", req.Name)
	}

	var h client.Handler
	switch {
	case typ == proto.TypeSSH && *local != "":
		addr, err := parseLocal(*local)
		if err != nil {
			return err
		}
		req.Local = addr
		h = client.ForwardHandler{Addr: addr}
	case typ == proto.TypeSSH:
		dir, err := client.ConfigDir()
		if err != nil {
			return err
		}
		sshd, err := client.NewSSHServer(filepath.Join(dir, "ssh_host_ed25519_key"), *shell)
		if err != nil {
			return err
		}
		req.Embedded = true
		req.Local = "built-in sshd"
		h = sshd
	default:
		if fs.NArg() != 1 {
			fs.Usage()
			os.Exit(2)
		}
		addr, err := parseLocal(fs.Arg(0))
		if err != nil {
			return err
		}
		req.Local = addr
		h = client.ForwardHandler{Addr: addr}
		if hostHeader != nil && *hostHeader != "" {
			req.HostHeader = *hostHeader
			if *hostHeader == "rewrite" {
				req.HostHeader = addr
			}
		}
	}

	ctx, cancel := signalContext()
	defer cancel()
	c := &client.Client{Config: cfg, Tunnels: []client.Tunnel{{Req: req, Handler: h}}}
	return c.Run(ctx)
}

// reorder moves positional args after flags so "bnat http 3000 -n app" works.
func reorder(args []string) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			if !strings.Contains(a, "=") && i+1 < len(args) && !isBoolFlag(a) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		pos = append(pos, a)
	}
	return append(flags, pos...)
}

func isBoolFlag(a string) bool {
	switch strings.TrimLeft(a, "-") {
	case "debug", "h", "help":
		return true
	}
	return false
}

func setupLog(debug bool) {
	lvl := slog.LevelInfo
	if debug {
		lvl = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})))
}

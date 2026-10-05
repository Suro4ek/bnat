package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Suro4ek/bnat/internal/service"
)

const serviceUsage = `usage: bnat service <command>

  install [--name N] [--user U] [--] <ssh|http|tcp|server> [args...]
                            run a tunnel (or the server) in the background, start at boot
  list                      installed bnat services
  status  [name]            state and recent output
  logs    [-f] [-n 100] [name]
  start | stop | restart [name]
  restart --all             restart every bnat service (used after updates)
  uninstall [name]

With sudo: a system service (systemd unit / LaunchDaemon) that starts at boot
and runs as the user who invoked sudo. Without sudo: a per-user service.

Examples:
  sudo bnat service install ssh -n home
  sudo bnat service install http 3000 -n app
  bnat service logs -f ssh-home
`

func runService(args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Print(serviceUsage)
		return nil
	}
	m, err := service.New()
	if err != nil {
		return err
	}
	cmd, args := args[0], args[1:]
	switch cmd {
	case "install":
		return serviceInstall(m, args)
	case "list", "ls":
		return serviceList(m)
	case "logs":
		fs := flag.NewFlagSet("logs", flag.ExitOnError)
		follow := fs.Bool("f", false, "follow")
		lines := fs.Int("n", 100, "number of lines")
		fs.Parse(reorder(args))
		name, err := serviceName(m, fs.Args())
		if err != nil {
			return err
		}
		return m.Logs(name, *lines, *follow)
	case "restart":
		if len(args) > 0 && args[0] == "--all" {
			return restartAll(m, len(args) > 1 && args[1] == "--quiet")
		}
		fallthrough
	case "status", "start", "stop", "uninstall", "remove":
		name, err := serviceName(m, args)
		if err != nil {
			return err
		}
		switch cmd {
		case "status":
			return m.Status(name)
		case "start":
			err = m.Start(name)
		case "stop":
			err = m.Stop(name)
		case "restart":
			err = m.Restart(name)
		default:
			err = m.Uninstall(name)
		}
		if err == nil {
			done := map[string]string{"start": "started", "stop": "stopped", "restart": "restarted", "uninstall": "uninstalled", "remove": "uninstalled"}
			fmt.Printf("%s: %s\n", name, done[cmd])
		}
		return err
	default:
		return fmt.Errorf("unknown service command %q\n\n%s", cmd, serviceUsage)
	}
}

// serviceName resolves the service to act on: an exact name, a tunnel name
// ("home" for "ssh-home") if unambiguous, or the only installed service.
func serviceName(m service.Manager, args []string) (string, error) {
	list, err := m.List()
	if err != nil {
		return "", err
	}
	if len(args) > 0 {
		return matchService(list, args[0]), nil
	}
	switch len(list) {
	case 0:
		return "", errors.New("no bnat services installed (see: bnat service install -h)")
	case 1:
		return list[0].Name, nil
	}
	names := make([]string, len(list))
	for i, s := range list {
		names[i] = s.Name
	}
	return "", fmt.Errorf("several services installed, pick one: %s", strings.Join(names, ", "))
}

// matchService maps a user-typed name to an installed service: exact match
// first, then a unique "<type>-<name>" match. Unknown names are returned as-is
// so the manager reports them as not found.
func matchService(list []service.Info, name string) string {
	var suffix []string
	for _, s := range list {
		if s.Name == name {
			return s.Name
		}
		if strings.HasSuffix(s.Name, "-"+name) {
			suffix = append(suffix, s.Name)
		}
	}
	if len(suffix) == 1 {
		return suffix[0]
	}
	return name
}

func serviceInstall(m service.Manager, args []string) error {
	fs := flag.NewFlagSet("service install", flag.ExitOnError)
	name := fs.String("name", "", "service name (default: derived from the command, e.g. ssh-home)")
	runAs := fs.String("user", "", "system services: account to run as (default: the user who ran sudo)")
	fs.Usage = func() { fmt.Fprint(os.Stderr, serviceUsage) }
	fs.Parse(args) // stops at the first non-flag or "--"
	bargs := fs.Args()
	// Accept tuna-style "-- bnat ssh ..." as well as "ssh ...".
	if len(bargs) > 0 && (bargs[0] == "bnat" || filepath.Base(bargs[0]) == "bnat") {
		bargs = bargs[1:]
	}
	if len(bargs) == 0 {
		fs.Usage()
		os.Exit(2)
	}
	kind := bargs[0]
	switch kind {
	case "ssh", "http", "tcp", "server":
	default:
		return fmt.Errorf("can only run ssh, http, tcp or server as a service, got %q", kind)
	}

	if *name == "" {
		*name = kind
		if n := flagValue(bargs[1:], "n", "name"); n != "" {
			*name = kind + "-" + n
		}
	}
	*name = strings.ToLower(*name)
	if !service.ValidName(*name) {
		return fmt.Errorf("invalid service name %q: use a-z, 0-9 and '-'", *name)
	}

	system := service.IsRoot()
	u, err := service.TargetUser(system, *runAs)
	if err != nil {
		return err
	}
	if kind == "server" && system && *runAs == "" {
		// The server binds :80/:443 and keeps state in /var/lib/bnat.
		if u, err = user.Current(); err != nil {
			return err
		}
	}
	cur, _ := user.Current()
	isCurrent := cur != nil && cur.Uid == u.Uid

	exe, err := service.Executable()
	if err != nil {
		return err
	}
	if strings.Contains(exe, os.TempDir()) || strings.Contains(exe, "go-build") {
		return fmt.Errorf("refusing to install %s (a temporary build); install bnat first", exe)
	}

	spec := service.Spec{Name: *name, Args: bargs, Exe: exe, System: system, User: u.Username, Home: u.HomeDir, Shell: service.LoginShell(u)}
	if kind == "server" {
		spec.WorkDir = filepath.Join(u.HomeDir, ".local", "share", "bnat")
		if system {
			spec.WorkDir = "/var/lib/bnat"
		}
		if err := os.MkdirAll(spec.WorkDir, 0o700); err != nil {
			return err
		}
	} else {
		spec.ConfigDir = service.ConfigDirFor(u, isCurrent)
		if _, err := os.Stat(filepath.Join(spec.ConfigDir, "config.json")); err != nil {
			hint := "bnat login https://bnat.example.com <CODE>"
			if !isCurrent {
				hint = fmt.Sprintf("run as %s (without sudo): %s", u.Username, hint)
			}
			return fmt.Errorf("%s is not logged in (no %s)\n  %s", u.Username, filepath.Join(spec.ConfigDir, "config.json"), hint)
		}
	}

	if flagValue(bargs, "admin-password") != "" {
		fmt.Fprintln(os.Stderr, "warning: --admin-password stays visible in `ps` and the service definition; drop it and a password is generated on first start (see the logs)")
	}
	if err := m.Install(spec); err != nil {
		var nr service.NeedRootError
		if errors.As(err, &nr) {
			return err
		}
		return fmt.Errorf("install %s: %w", *name, err)
	}

	scope := "user service"
	if system {
		scope = "system service, starts at boot"
	}
	sudo := ""
	if system {
		sudo = "sudo "
	}
	fmt.Printf("\n  ✓ installed %q (%s), running as %s\n    bnat %s\n\n", *name, scope, u.Username, strings.Join(bargs, " "))
	fmt.Printf("  status:  bnat service status %s\n  logs:    bnat service logs -f %s\n  remove:  %sbnat service uninstall %s\n\n", *name, *name, sudo, *name)
	return nil
}

// flagValue finds -n/--name style values in raw args.
func flagValue(args []string, names ...string) string {
	for i, a := range args {
		for _, n := range names {
			for _, p := range []string{"-" + n, "--" + n} {
				if a == p && i+1 < len(args) {
					return args[i+1]
				}
				if v, ok := strings.CutPrefix(a, p+"="); ok {
					return v
				}
			}
		}
	}
	return ""
}

func serviceList(m service.Manager) error {
	list, err := m.List()
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Println("no bnat services installed")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "NAME\tSTATE\tSCOPE\tCOMMAND")
	for _, s := range list {
		state, scope := "stopped", "user"
		if s.Running {
			state = "running"
		}
		if s.System {
			scope = "system"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\tbnat %s\n", s.Name, state, scope, s.Command)
	}
	return w.Flush()
}

// restartAll restarts the services this user may manage: system ones as root,
// per-user ones otherwise.
func restartAll(m service.Manager, quiet bool) error {
	list, err := m.List()
	if err != nil {
		return err
	}
	var failed []string
	n := 0
	for _, s := range list {
		if s.System != service.IsRoot() {
			continue
		}
		n++
		if err := m.Restart(s.Name); err != nil {
			failed = append(failed, s.Name)
			continue
		}
		fmt.Printf("restarted %s\n", s.Name)
	}
	if n == 0 && !quiet {
		fmt.Println("no bnat services to restart")
	}
	if len(failed) > 0 {
		return fmt.Errorf("failed to restart: %s", strings.Join(failed, ", "))
	}
	return nil
}

// Installer locations, tried in order. BNAT_INSTALL_SCRIPT_URL (a mirror,
// testing) goes first when set; the release mirror covers networks where
// GitHub is blocked.
var installScripts = []string{
	"https://raw.githubusercontent.com/Suro4ek/bnat/main/install.sh",
	"https://release.bnat.ctai.dev/install.sh",
}

// fetchInstaller downloads install.sh from the first location that answers.
func fetchInstaller() (string, error) {
	srcs := installScripts
	if v := os.Getenv("BNAT_INSTALL_SCRIPT_URL"); v != "" {
		srcs = []string{v}
	}
	var errs []string
	for _, src := range srcs {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			var b []byte
			if resp.StatusCode == http.StatusOK {
				b, err = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			} else {
				err = fmt.Errorf("HTTP %d", resp.StatusCode)
			}
			resp.Body.Close()
			if err == nil && strings.HasPrefix(string(b), "#!") {
				cancel()
				return string(b), nil
			}
			if err == nil {
				err = errors.New("not a shell script")
			}
		}
		cancel()
		errs = append(errs, fmt.Sprintf("%s: %v", src, err))
	}
	return "", fmt.Errorf("download installer:\n  %s", strings.Join(errs, "\n  "))
}

func runUpdate(args []string) error {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: bnat update [version]   (default: latest release)")
	}
	fs.Parse(args)
	if runtime.GOOS == "windows" {
		return errors.New("on Windows, download the new .zip from https://github.com/Suro4ek/bnat/releases")
	}
	exe, err := service.Executable()
	if err != nil {
		return err
	}
	script, err := fetchInstaller()
	if err != nil {
		return err
	}
	cmd := exec.Command("sh", "-s")
	cmd.Stdin = strings.NewReader(script)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.Env = append(os.Environ(), "BNAT_INSTALL_DIR="+filepath.Dir(exe), "BNAT_UPDATE=1")
	if fs.NArg() > 0 {
		cmd.Env = append(cmd.Env, "BNAT_VERSION="+fs.Arg(0))
	}
	return cmd.Run()
}

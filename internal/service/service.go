// Package service installs bnat as a background service: systemd on Linux,
// launchd on macOS. Running as root installs a system service that starts at
// boot; otherwise a per-user service is installed.
package service

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// Spec describes a service to install.
type Spec struct {
	Name      string   // short name, e.g. "ssh-home"
	Args      []string // bnat arguments, e.g. ["ssh", "-n", "home"]
	Exe       string   // absolute path to the bnat binary
	System    bool     // system-wide service (root) vs per-user
	User      string   // system services: account to run as ("" = root)
	Home      string   // HOME of that account
	Shell     string   // login shell of that account (launchd doesn't set it)
	ConfigDir string   // BNAT_CONFIG_DIR for the process ("" = default)
	WorkDir   string   // working directory ("" = home)
}

// Info describes an installed service.
type Info struct {
	Name    string
	System  bool
	Command string
	Running bool
}

type Manager interface {
	Install(s Spec) error
	Uninstall(name string) error
	Start(name string) error
	Stop(name string) error
	Restart(name string) error
	// Status prints the service state to stdout.
	Status(name string) error
	// Logs prints (and with follow, streams) recent output to stdout.
	Logs(name string, lines int, follow bool) error
	List() ([]Info, error)
	// LogHint tells the user how to read logs outside of bnat.
	LogHint(name string) string
}

var (
	ErrNotFound    = errors.New("service not found")
	ErrUnsupported = fmt.Errorf("services are not supported on %s yet", runtime.GOOS)
)

// NeedRootError is returned when a system service is managed without root.
type NeedRootError struct{ Name string }

func (e NeedRootError) Error() string {
	return fmt.Sprintf("%s is a system service: run this command with sudo", e.Name)
}

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)

func ValidName(n string) bool { return nameRe.MatchString(n) }

// New returns the service manager for this OS.
func New() (Manager, error) {
	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("systemctl"); err != nil {
			return nil, errors.New("systemd (systemctl) not found; run `bnat ...` under your init system manually")
		}
		return systemd{}, nil
	case "darwin":
		return launchd{}, nil
	default:
		return nil, ErrUnsupported
	}
}

func IsRoot() bool { return os.Geteuid() == 0 }

// TargetUser resolves which account a service runs as and its home directory.
// For system services it is the explicit user, else the one who invoked sudo,
// else root. Per-user services always run as the current user.
func TargetUser(system bool, explicit string) (*user.User, error) {
	if !system {
		if explicit != "" {
			return nil, errors.New("--user needs a system service: run with sudo")
		}
		return user.Current()
	}
	name := explicit
	if name == "" {
		name = os.Getenv("SUDO_USER")
	}
	if name == "" {
		return user.Current()
	}
	return user.Lookup(name)
}

// ConfigDirFor returns where bnat keeps its login for the given account,
// mirroring client.ConfigDir for that user's home.
func ConfigDirFor(u *user.User, current bool) string {
	if d := os.Getenv("BNAT_CONFIG_DIR"); d != "" {
		return d
	}
	if current {
		if d, err := os.UserConfigDir(); err == nil {
			return filepath.Join(d, "bnat")
		}
	}
	if runtime.GOOS == "darwin" {
		return filepath.Join(u.HomeDir, "Library", "Application Support", "bnat")
	}
	return filepath.Join(u.HomeDir, ".config", "bnat")
}

// LoginShell returns the account's login shell.
func LoginShell(u *user.User) string {
	switch runtime.GOOS {
	case "darwin":
		out, err := exec.Command("dscl", ".", "-read", "/Users/"+u.Username, "UserShell").Output()
		if err == nil {
			if f := strings.Fields(string(out)); len(f) == 2 {
				return f[1]
			}
		}
		return "/bin/zsh"
	default:
		if b, err := os.ReadFile("/etc/passwd"); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				f := strings.Split(line, ":")
				if len(f) == 7 && f[0] == u.Username {
					return f[6]
				}
			}
		}
		return "/bin/sh"
	}
}

// Executable returns the resolved path of the running bnat binary.
func Executable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// commandLine renders args for display.
func commandLine(args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		if a == "" || strings.ContainsAny(a, " \t\"'\\$`") {
			a = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
		q[i] = a
	}
	return strings.Join(q, " ")
}

// run executes a command with output passed through to the user.
func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func writeFile(path, content string, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

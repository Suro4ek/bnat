package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type systemd struct{}

const systemUnitDir = "/etc/systemd/system"

func unitFile(name string) string { return "bnat-" + name + ".service" }

func userUnitDir() string {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "systemd", "user")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "systemd", "user")
}

func unitDir(system bool) string {
	if system {
		return systemUnitDir
	}
	return userUnitDir()
}

// locate finds an installed unit, preferring the system one.
func (systemd) locate(name string) (system bool, err error) {
	if exists(filepath.Join(systemUnitDir, unitFile(name))) {
		return true, nil
	}
	if exists(filepath.Join(userUnitDir(), unitFile(name))) {
		return false, nil
	}
	return false, fmt.Errorf("%w: %s", ErrNotFound, name)
}

func ctl(system bool, args ...string) error {
	if !system {
		args = append([]string{"--user"}, args...)
	}
	return run("systemctl", args...)
}

// systemdQuote quotes an ExecStart argument (systemd.syntax(7)).
func systemdQuote(a string) string {
	a = strings.ReplaceAll(a, "%", "%%")
	a = strings.ReplaceAll(a, "$", "$$")
	if a != "" && !strings.ContainsAny(a, " \t\"'\\;") {
		return a
	}
	a = strings.ReplaceAll(a, `\`, `\\`)
	a = strings.ReplaceAll(a, `"`, `\"`)
	return `"` + a + `"`
}

func renderUnit(s Spec) string {
	var b strings.Builder
	exec := make([]string, 0, len(s.Args)+1)
	for _, a := range append([]string{s.Exe}, s.Args...) {
		exec = append(exec, systemdQuote(a))
	}
	fmt.Fprintf(&b, "# Managed by bnat: bnat service uninstall %s\n", s.Name)
	fmt.Fprintf(&b, "[Unit]\nDescription=bnat %s\n", commandLine(s.Args))
	b.WriteString("After=network-online.target\nWants=network-online.target\nStartLimitIntervalSec=0\n\n")
	b.WriteString("[Service]\nType=simple\n")
	if s.System && s.User != "" && s.User != "root" {
		fmt.Fprintf(&b, "User=%s\n", s.User)
	}
	if s.ConfigDir != "" {
		fmt.Fprintf(&b, "Environment=%s\n", systemdQuote("BNAT_CONFIG_DIR="+s.ConfigDir))
	}
	if s.WorkDir != "" {
		fmt.Fprintf(&b, "WorkingDirectory=%s\n", systemdQuote(s.WorkDir))
	} else if s.System {
		b.WriteString("WorkingDirectory=~\n")
	}
	fmt.Fprintf(&b, "ExecStart=%s\n", strings.Join(exec, " "))
	b.WriteString("Restart=always\nRestartSec=5\n\n")
	b.WriteString("[Install]\n")
	if s.System {
		b.WriteString("WantedBy=multi-user.target\n")
	} else {
		b.WriteString("WantedBy=default.target\n")
	}
	return b.String()
}

func (m systemd) Install(s Spec) error {
	if s.System && !IsRoot() {
		return NeedRootError{s.Name}
	}
	path := filepath.Join(unitDir(s.System), unitFile(s.Name))
	// Arguments may carry secrets (e.g. --admin-password): keep system units root-only.
	if err := writeFile(path, renderUnit(s), 0o600); err != nil {
		return err
	}
	if err := ctl(s.System, "daemon-reload"); err != nil {
		return err
	}
	if !s.System {
		// Without lingering, user services stop at logout and don't start at boot.
		if u := os.Getenv("USER"); u != "" {
			if err := exec.Command("loginctl", "enable-linger", u).Run(); err != nil {
				fmt.Fprintf(os.Stderr, "warning: `loginctl enable-linger %s` failed; the service will only run while you're logged in (or install it with sudo)\n", u)
			}
		}
	}
	if err := ctl(s.System, "enable", unitFile(s.Name)); err != nil {
		return err
	}
	return ctl(s.System, "restart", unitFile(s.Name))
}

func (m systemd) control(name string, root bool, args ...string) error {
	system, err := m.locate(name)
	if err != nil {
		return err
	}
	if system && root && !IsRoot() {
		return NeedRootError{name}
	}
	return ctl(system, append(args, unitFile(name))...)
}

func (m systemd) Uninstall(name string) error {
	system, err := m.locate(name)
	if err != nil {
		return err
	}
	if system && !IsRoot() {
		return NeedRootError{name}
	}
	ctl(system, "disable", "--now", unitFile(name))
	if err := os.Remove(filepath.Join(unitDir(system), unitFile(name))); err != nil {
		return err
	}
	return ctl(system, "daemon-reload")
}

func (m systemd) Start(name string) error   { return m.control(name, true, "start") }
func (m systemd) Stop(name string) error    { return m.control(name, true, "stop") }
func (m systemd) Restart(name string) error { return m.control(name, true, "restart") }

func (m systemd) Status(name string) error {
	err := m.control(name, false, "status", "--no-pager", "--lines=15")
	if _, ok := err.(*exec.ExitError); ok {
		return nil // non-zero just means "not running"; the output says so
	}
	return err
}

func (m systemd) Logs(name string, lines int, follow bool) error {
	system, err := m.locate(name)
	if err != nil {
		return err
	}
	args := []string{"-u", unitFile(name), "-n", strconv.Itoa(lines), "--no-pager", "-o", "cat"}
	if !system {
		args = append([]string{"--user"}, args...)
	}
	if follow {
		args = append(args, "-f")
	}
	return run("journalctl", args...)
}

func (m systemd) LogHint(name string) string {
	system, _ := m.locate(name)
	if system {
		return "journalctl -u " + unitFile(name) + " -f"
	}
	return "journalctl --user -u " + unitFile(name) + " -f"
}

func (m systemd) List() ([]Info, error) {
	var out []Info
	for _, system := range []bool{true, false} {
		files, _ := filepath.Glob(filepath.Join(unitDir(system), "bnat-*.service"))
		for _, f := range files {
			name := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), "bnat-"), ".service")
			info := Info{Name: name, System: system, Command: unitCommand(f)}
			args := []string{"is-active", "--quiet", unitFile(name)}
			if !system {
				args = append([]string{"--user"}, args...)
			}
			info.Running = exec.Command("systemctl", args...).Run() == nil
			out = append(out, info)
		}
	}
	return out, nil
}

// unitCommand extracts the bnat arguments from a unit's ExecStart.
func unitCommand(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if d, ok := strings.CutPrefix(line, "Description=bnat "); ok {
			return d
		}
	}
	return ""
}

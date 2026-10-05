package service

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type launchd struct{}

const labelPrefix = "com.github.suro4ek.bnat."

func label(name string) string { return labelPrefix + name }

func plistPath(system bool, name string) string {
	if system {
		return filepath.Join("/Library/LaunchDaemons", label(name)+".plist")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", label(name)+".plist")
}

func logPath(system bool, name string) string {
	if system {
		return filepath.Join("/Library/Logs/bnat", name+".log")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "Logs", "bnat", name+".log")
}

func domain(system bool) string {
	if system {
		return "system"
	}
	return "gui/" + strconv.Itoa(os.Getuid())
}

func target(system bool, name string) string { return domain(system) + "/" + label(name) }

func (launchd) locate(name string) (bool, error) {
	if exists(plistPath(true, name)) {
		return true, nil
	}
	if exists(plistPath(false, name)) {
		return false, nil
	}
	return false, fmt.Errorf("%w: %s", ErrNotFound, name)
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

func renderPlist(s Spec) string {
	var b strings.Builder
	str := func(v string) string { return "<string>" + xmlEscape(v) + "</string>" }
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- Managed by bnat: bnat service uninstall ` + xmlEscape(s.Name) + ` -->
<plist version="1.0">
<dict>
  <key>Label</key>` + str(label(s.Name)) + `
  <key>ProgramArguments</key>
  <array>
`)
	for _, a := range append([]string{s.Exe}, s.Args...) {
		b.WriteString("    " + str(a) + "\n")
	}
	b.WriteString("  </array>\n")
	if s.System && s.User != "" && s.User != "root" {
		b.WriteString("  <key>UserName</key>" + str(s.User) + "\n")
	}
	env := map[string]string{"PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"}
	if s.Home != "" {
		env["HOME"] = s.Home
	}
	if s.Shell != "" {
		env["SHELL"] = s.Shell
	}
	if s.User != "" {
		env["USER"] = s.User
	}
	if s.ConfigDir != "" {
		env["BNAT_CONFIG_DIR"] = s.ConfigDir
	}
	b.WriteString("  <key>EnvironmentVariables</key>\n  <dict>\n")
	for _, k := range []string{"PATH", "HOME", "USER", "SHELL", "BNAT_CONFIG_DIR"} {
		if v, ok := env[k]; ok {
			b.WriteString("    <key>" + k + "</key>" + str(v) + "\n")
		}
	}
	b.WriteString("  </dict>\n")
	wd := s.WorkDir
	if wd == "" {
		wd = s.Home
	}
	if wd != "" {
		b.WriteString("  <key>WorkingDirectory</key>" + str(wd) + "\n")
	}
	log := logPath(s.System, s.Name)
	b.WriteString(`  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>5</integer>
  <key>StandardOutPath</key>` + str(log) + `
  <key>StandardErrorPath</key>` + str(log) + `
</dict>
</plist>
`)
	return b.String()
}

func (m launchd) Install(s Spec) error {
	if s.System && !IsRoot() {
		return NeedRootError{s.Name}
	}
	log := logPath(s.System, s.Name)
	if err := os.MkdirAll(filepath.Dir(log), 0o755); err != nil {
		return err
	}
	// launchd opens the log as the service user, so let it own the file.
	if f, err := os.OpenFile(log, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
		f.Close()
		if s.System && s.User != "" {
			exec.Command("chown", s.User, log).Run()
		}
	}
	path := plistPath(s.System, s.Name)
	if err := writeFile(path, renderPlist(s), 0o644); err != nil {
		return err
	}
	exec.Command("launchctl", "bootout", target(s.System, s.Name)).Run()
	exec.Command("launchctl", "enable", target(s.System, s.Name)).Run()
	return run("launchctl", "bootstrap", domain(s.System), path)
}

func (m launchd) loaded(system bool, name string) bool {
	return exec.Command("launchctl", "print", target(system, name)).Run() == nil
}

func (m launchd) find(name string, root bool) (bool, error) {
	system, err := m.locate(name)
	if err != nil {
		return false, err
	}
	if system && root && !IsRoot() {
		return false, NeedRootError{name}
	}
	return system, nil
}

func (m launchd) Uninstall(name string) error {
	system, err := m.find(name, true)
	if err != nil {
		return err
	}
	exec.Command("launchctl", "bootout", target(system, name)).Run()
	return os.Remove(plistPath(system, name))
}

func (m launchd) Start(name string) error {
	system, err := m.find(name, true)
	if err != nil {
		return err
	}
	if m.loaded(system, name) {
		return run("launchctl", "kickstart", target(system, name))
	}
	return run("launchctl", "bootstrap", domain(system), plistPath(system, name))
}

func (m launchd) Stop(name string) error {
	system, err := m.find(name, true)
	if err != nil {
		return err
	}
	if !m.loaded(system, name) {
		return nil
	}
	return run("launchctl", "bootout", target(system, name))
}

func (m launchd) Restart(name string) error {
	system, err := m.find(name, true)
	if err != nil {
		return err
	}
	if !m.loaded(system, name) {
		return run("launchctl", "bootstrap", domain(system), plistPath(system, name))
	}
	return run("launchctl", "kickstart", "-k", target(system, name))
}

// state returns launchd's view of the job: running and pid, or "not loaded".
func (m launchd) state(system bool, name string) (running bool, pid string, lastExit string) {
	out, err := exec.Command("launchctl", "print", target(system, name)).Output()
	if err != nil {
		return false, "", ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "state = running":
			running = true
		case strings.HasPrefix(line, "pid = "):
			pid = strings.TrimPrefix(line, "pid = ")
		case strings.HasPrefix(line, "last exit code = "):
			lastExit = strings.TrimPrefix(line, "last exit code = ")
		}
	}
	return
}

func (m launchd) Status(name string) error {
	system, err := m.locate(name)
	if err != nil {
		return err
	}
	scope := "user service (LaunchAgent)"
	if system {
		scope = "system service (LaunchDaemon)"
	}
	fmt.Printf("● %s — %s\n", label(name), scope)
	switch running, pid, lastExit := m.state(system, name); {
	case running:
		fmt.Printf("  state: running (pid %s)\n", pid)
	case m.loaded(system, name):
		fmt.Printf("  state: not running, restarting (last exit: %s)\n", lastExit)
	default:
		fmt.Println("  state: stopped")
	}
	fmt.Printf("  plist: %s\n  log:   %s\n\n", plistPath(system, name), logPath(system, name))
	return run("tail", "-n", "15", logPath(system, name))
}

func (m launchd) Logs(name string, lines int, follow bool) error {
	system, err := m.locate(name)
	if err != nil {
		return err
	}
	args := []string{"-n", strconv.Itoa(lines)}
	if follow {
		args = append(args, "-F")
	}
	return run("tail", append(args, logPath(system, name))...)
}

func (m launchd) LogHint(name string) string {
	system, _ := m.locate(name)
	return "tail -F " + logPath(system, name)
}

func (m launchd) List() ([]Info, error) {
	var out []Info
	for _, system := range []bool{true, false} {
		files, _ := filepath.Glob(filepath.Join(filepath.Dir(plistPath(system, "x")), labelPrefix+"*.plist"))
		for _, f := range files {
			name := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), labelPrefix), ".plist")
			running, _, _ := m.state(system, name)
			out = append(out, Info{Name: name, System: system, Running: running, Command: plistCommand(f)})
		}
	}
	return out, nil
}

// plistCommand reads ProgramArguments back for display (skipping the binary).
func plistCommand(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return plistCommandFrom(string(b))
}

func plistCommandFrom(plist string) string {
	_, rest, ok := strings.Cut(plist, "<key>ProgramArguments</key>")
	if !ok {
		return ""
	}
	arr, _, _ := strings.Cut(rest, "</array>")
	var args []string
	for _, part := range strings.Split(arr, "<string>")[1:] {
		v, _, _ := strings.Cut(part, "</string>")
		var s string
		if xml.Unmarshal([]byte("<s>"+v+"</s>"), &s) == nil {
			args = append(args, s)
		}
	}
	if len(args) > 1 {
		return commandLine(args[1:])
	}
	return ""
}

package service

import (
	"strings"
	"testing"
)

func TestRenderUnit(t *testing.T) {
	u := renderUnit(Spec{
		Name: "http-app", System: true, User: "alice", Exe: "/usr/local/bin/bnat",
		Args:      []string{"http", "3000", "-n", "app", "--host-header", "my host:3000", "--x=100%$HOME"},
		ConfigDir: "/home/alice/.config/bnat",
	})
	for _, want := range []string{
		"User=alice\n",
		"Environment=BNAT_CONFIG_DIR=/home/alice/.config/bnat\n",
		`ExecStart=/usr/local/bin/bnat http 3000 -n app --host-header "my host:3000" --x=100%%$$HOME` + "\n",
		"Restart=always\n",
		"WantedBy=multi-user.target\n",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit is missing %q:\n%s", want, u)
		}
	}

	user := renderUnit(Spec{Name: "ssh", Exe: "/b", Args: []string{"ssh"}})
	if strings.Contains(user, "User=") || !strings.Contains(user, "WantedBy=default.target") {
		t.Errorf("per-user unit:\n%s", user)
	}
}

func TestRenderPlist(t *testing.T) {
	p := renderPlist(Spec{
		Name: "ssh-home", System: true, User: "alice", Home: "/Users/alice", Shell: "/bin/zsh",
		Exe: "/usr/local/bin/bnat", Args: []string{"ssh", "-n", "home & <co>"}, ConfigDir: "/Users/alice/Library/Application Support/bnat",
	})
	for _, want := range []string{
		"<key>Label</key><string>com.github.suro4ek.bnat.ssh-home</string>",
		"<string>home &amp; &lt;co&gt;</string>",
		"<key>UserName</key><string>alice</string>",
		"<key>SHELL</key><string>/bin/zsh</string>",
		"<key>KeepAlive</key><true/>",
		"/Library/Logs/bnat/ssh-home.log",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("plist is missing %q:\n%s", want, p)
		}
	}
	if got := plistCommandFrom(p); got != "ssh -n 'home & <co>'" {
		t.Errorf("command read back as %q", got)
	}
}

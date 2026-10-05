package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Suro4ek/bnat/internal/service"
)

func TestMatchService(t *testing.T) {
	list := []service.Info{{Name: "ssh-home"}, {Name: "http-web"}, {Name: "tcp-web"}, {Name: "server"}}
	for in, want := range map[string]string{
		"ssh-home": "ssh-home", // exact
		"home":     "ssh-home", // tunnel name
		"server":   "server",
		"web":      "web", // ambiguous: http-web and tcp-web
		"nope":     "nope",
	} {
		if got := matchService(list, in); got != want {
			t.Errorf("matchService(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFlagValue(t *testing.T) {
	args := []string{"3000", "-n", "app", "--host-header=rewrite"}
	if v := flagValue(args, "n", "name"); v != "app" {
		t.Errorf("-n: got %q", v)
	}
	if v := flagValue(args, "host-header"); v != "rewrite" {
		t.Errorf("--host-header=: got %q", v)
	}
	if v := flagValue([]string{"--name=box"}, "n", "name"); v != "box" {
		t.Errorf("--name=: got %q", v)
	}
}

func TestFetchInstallerFallsBack(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "#!/bin/sh\necho mirror\n")
	}))
	defer good.Close()
	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "blocked", http.StatusForbidden)
	}))
	defer blocked.Close()

	old := installScripts
	defer func() { installScripts = old }()
	installScripts = []string{"http://127.0.0.1:9/install.sh", blocked.URL + "/install.sh", good.URL + "/install.sh"}
	t.Setenv("BNAT_INSTALL_SCRIPT_URL", "")

	script, err := fetchInstaller()
	if err != nil || !strings.Contains(script, "echo mirror") {
		t.Fatalf("got %q, %v", script, err)
	}
}

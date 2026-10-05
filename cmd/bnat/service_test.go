package main

import (
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

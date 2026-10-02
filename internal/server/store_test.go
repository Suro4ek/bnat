package server

import (
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestPairing(t *testing.T) {
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	code, err := st.CreateClient("box")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := st.Authenticate(""); ok {
		t.Fatal("empty token authenticated an unpaired client")
	}

	c, tok, err := st.Pair(" "+code[:4]+code[5:]+" ", "host", "user") // no dash, extra spaces
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	if !c.Paired() || c.Hostname != "host" || c.PairPending() {
		t.Fatalf("unexpected client state %+v", c)
	}
	if _, ok := st.Authenticate(tok); !ok {
		t.Fatal("issued token does not authenticate")
	}

	// Re-pairing replaces the token.
	_, code2, err := st.NewPairCode(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := st.Authenticate(tok); !ok {
		t.Fatal("old token must keep working until the new code is used")
	}
	_, tok2, err := st.Pair(code2, "host2", "user")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := st.Authenticate(tok); ok {
		t.Fatal("old token still works after re-pairing")
	}
	if _, ok := st.Authenticate(tok2); !ok {
		t.Fatal("new token does not authenticate")
	}
}

func TestPairCodeExpires(t *testing.T) {
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	code, _ := st.CreateClient("box")
	st.update(func(d *data) error {
		d.Tokens[0].PairExpires = time.Now().Add(-time.Second)
		return nil
	})
	if _, _, err := st.Pair(code, "h", "u"); !errors.Is(err, ErrBadPairCode) {
		t.Fatalf("expired code: got %v", err)
	}
}

func TestStorePersists(t *testing.T) {
	dir := t.TempDir()
	st, _ := OpenStore(dir)
	st.CreateClient("box")
	_, pub := newSSHKey(t)
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " me@laptop"
	if err := st.AddKey("", line, nil); err != nil {
		t.Fatal(err)
	}
	st2, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(st2.Tokens()) != 1 || len(st2.Keys()) != 1 || st2.Keys()[0].Name != "me@laptop" {
		t.Fatalf("data not persisted: %+v %+v", st2.Tokens(), st2.Keys())
	}
	if string(st.Secret()) != string(st2.Secret()) {
		t.Fatal("session secret changed across restarts")
	}
}

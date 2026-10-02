package proto

import (
	"bytes"
	"testing"
)

func TestHeaderRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	want := StreamHeader{Tunnel: "box", Remote: "1.2.3.4:5678"}
	if err := WriteHeader(&buf, want); err != nil {
		t.Fatal(err)
	}
	buf.WriteString("payload")
	got, err := ReadHeader(&buf)
	if err != nil || got != want {
		t.Fatalf("got %+v, %v", got, err)
	}
	if buf.String() != "payload" {
		t.Fatalf("header read consumed payload: %q left", buf.String())
	}
}

func TestValidName(t *testing.T) {
	for name, ok := range map[string]bool{
		"box": true, "my-host-1": true, "a": true,
		"": false, "-x": false, "x-": false, "Box": false, "a.b": false, "a_b": false,
	} {
		if ValidName(name) != ok {
			t.Errorf("ValidName(%q) = %v, want %v", name, !ok, ok)
		}
	}
}

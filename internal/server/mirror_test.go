package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Suro4ek/bnat/internal/proto"
)

func TestReleaseMirror(t *testing.T) {
	var hits atomic.Int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/latest":
			http.Redirect(w, r, "/releases/tag/v1.2.3", http.StatusFound)
		case "/download/v1.2.3/checksums.txt":
			io.WriteString(w, "abc  bnat_1.2.3_linux_amd64.tar.gz\n")
		case "/download/v1.2.3/bnat_1.2.3_linux_amd64.tar.gz":
			io.WriteString(w, "BINARY")
		default:
			http.NotFound(w, r)
		}
	}))
	dataDir := t.TempDir()
	s, err := New(Config{
		Domain: "bnat.example.com", HTTPAddr: ":80", DataDir: dataDir, AdminPassword: "x", PortMin: 1, PortMax: 2,
		ReleasesHost: "release.bnat.example.com", ReleasesUpstream: up.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	get := func(method, path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, httptest.NewRequest(method, "http://release.bnat.example.com"+path, nil))
		return rec
	}

	t.Run("install.sh points at the mirror", func(t *testing.T) {
		body := get("GET", "/install.sh").Body.String()
		for _, want := range []string{
			`primary="${BNAT_DOWNLOAD_BASE:-http://release.bnat.example.com}" # bnat:primary`,
			`fallback="${BNAT_FALLBACK_BASE-` + up.URL + `}" # bnat:fallback`,
			"curl -fsSL http://release.bnat.example.com/install.sh | sh",
		} {
			if !strings.Contains(body, want) {
				t.Errorf("served install.sh lacks %q", want)
			}
		}
		if strings.Contains(body, "raw.githubusercontent.com") {
			t.Error("served install.sh still references GitHub raw")
		}
	})

	t.Run("latest", func(t *testing.T) {
		rec := get("HEAD", "/latest")
		if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/tag/v1.2.3" {
			t.Fatalf("got %d %q", rec.Code, rec.Header().Get("Location"))
		}
		if rec := get("HEAD", "/tag/v1.2.3"); rec.Code != http.StatusOK {
			t.Fatalf("tag page: %d", rec.Code)
		}
	})

	t.Run("new release is prefetched", func(t *testing.T) {
		waitFor(t, "prefetch", func() bool {
			_, err := os.Stat(filepath.Join(dataDir, "releases", "v1.2.3", "bnat_1.2.3_linux_amd64.tar.gz"))
			return err == nil
		})
	})

	t.Run("files", func(t *testing.T) {
		if rec := get("GET", "/download/v1.2.3/bnat_1.2.3_linux_amd64.tar.gz"); rec.Body.String() != "BINARY" {
			t.Fatalf("got %d %q", rec.Code, rec.Body.String())
		}
		if rec := get("GET", "/download/v1.2.3/bnat_1.2.3_darwin_arm64.tar.gz"); rec.Code != http.StatusNotFound {
			t.Fatalf("missing upstream file: got %d, want 404", rec.Code)
		}
		for _, bad := range []string{"/download/v1.2.3/../../bnat.json", "/download/v1.2.3/evil.sh", "/download/latest/checksums.txt", "/download/v1.2.3"} {
			if rec := get("GET", bad); rec.Code != http.StatusNotFound {
				t.Errorf("%s: got %d, want 404", bad, rec.Code)
			}
		}
	})

	t.Run("works with upstream down", func(t *testing.T) {
		up.Close()
		s.mirror.mu.Lock()
		s.mirror.checkedAt = time.Time{} // force a re-check against the dead upstream
		s.mirror.mu.Unlock()
		if rec := get("HEAD", "/latest"); rec.Header().Get("Location") != "/tag/v1.2.3" {
			t.Fatalf("latest with upstream down: %d %q", rec.Code, rec.Header().Get("Location"))
		}
		if rec := get("GET", "/download/v1.2.3/checksums.txt"); rec.Code != http.StatusOK {
			t.Fatalf("cached file with upstream down: %d", rec.Code)
		}
		if rec := get("GET", "/download/v9.9.9/checksums.txt"); rec.Code != http.StatusBadGateway {
			t.Fatalf("uncached file with upstream down: %d, want 502", rec.Code)
		}
	})

	t.Run("latest survives restart", func(t *testing.T) {
		m := newMirror("http://x", "http://127.0.0.1:1", filepath.Join(dataDir, "releases"), s.log)
		if m.latest != "v1.2.3" {
			t.Fatalf("latest after restart = %q", m.latest)
		}
	})

	t.Run("old releases are pruned", func(t *testing.T) {
		dir := filepath.Join(dataDir, "releases")
		for i, tag := range []string{"v0.0.1", "v0.0.2", "v0.0.3", "v0.0.4", "v0.0.5", "v0.0.6"} {
			os.MkdirAll(filepath.Join(dir, tag), 0o755)
			old := time.Now().Add(-time.Duration(10-i) * time.Hour)
			os.Chtimes(filepath.Join(dir, tag), old, old)
		}
		s.mirror.prune("v1.2.3")
		var left []string
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if e.IsDir() {
				left = append(left, e.Name())
			}
		}
		if strings.Join(left, " ") != "v0.0.3 v0.0.4 v0.0.5 v0.0.6 v1.2.3" {
			t.Fatalf("after prune: %v", left)
		}
	})

	t.Run("name is reserved", func(t *testing.T) {
		info := s.register(&agentSession{}, proto.TunnelReq{Name: "release", Type: proto.TypeHTTP})
		if !strings.Contains(info.Error, "reserved") {
			t.Fatalf("tunnel took the mirror's name: %+v", info)
		}
	})
}

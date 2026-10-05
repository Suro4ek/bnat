package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Suro4ek/bnat"
)

// mirror serves install.sh and bnat release files on a dedicated host, for
// clients that can't reach GitHub. Files are fetched from GitHub on first use
// (and for each new release, ahead of time) and kept on disk, so already
// mirrored versions stay available even if GitHub becomes unreachable.
//
// URL layout matches GitHub's, so install.sh works against either:
//
//	/install.sh              installer that downloads from this mirror
//	/latest                  302 → /tag/<latest tag>
//	/download/<tag>/<file>   release asset
type mirror struct {
	self     string // public base URL of the mirror, e.g. https://release.bnat.example.com
	upstream string // e.g. https://github.com/Suro4ek/bnat/releases
	rawURL   string // install.sh URL on GitHub, replaced by the mirror's own in the served script
	dir      string
	client   *http.Client
	log      *slog.Logger

	mu        sync.Mutex
	latest    string
	checkedAt time.Time
	fetching  map[string]*sync.Mutex
}

const (
	mirrorLatestTTL = 5 * time.Minute
	mirrorKeep      = 5 // releases kept on disk; older ones are re-fetched on demand
	mirrorMaxFile   = 200 << 20
	githubRawScript = "https://raw.githubusercontent.com/Suro4ek/bnat/main/install.sh"
)

var (
	mirrorTagRe  = regexp.MustCompile(`^v[0-9][0-9A-Za-z.+-]{0,40}$`)
	mirrorFileRe = regexp.MustCompile(`^(bnat_[0-9A-Za-z.+_-]{1,80}\.(tar\.gz|zip)|checksums\.txt)$`)
)

func newMirror(self, upstream, dir string, log *slog.Logger) *mirror {
	m := &mirror{
		self:     strings.TrimRight(self, "/"),
		upstream: strings.TrimRight(upstream, "/"),
		rawURL:   githubRawScript,
		dir:      dir,
		log:      log.With("component", "mirror"),
		fetching: map[string]*sync.Mutex{},
		client: &http.Client{
			Timeout: 10 * time.Minute,
			// /releases/latest answers with a redirect we want to read, not follow.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if strings.HasSuffix(via[0].URL.Path, "/latest") {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
	if b, err := os.ReadFile(filepath.Join(dir, "latest")); err == nil {
		m.latest = strings.TrimSpace(string(b))
	}
	return m
}

func (m *mirror) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	path := r.URL.Path
	switch {
	case path == "/" || path == "":
		m.index(w, r)
	case path == "/install.sh":
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		io.WriteString(w, m.script())
	case path == "/latest":
		tag, err := m.latestTag(r.Context())
		if err != nil {
			http.Error(w, "latest release unknown: "+err.Error(), http.StatusBadGateway)
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		http.Redirect(w, r, "/tag/"+tag, http.StatusFound)
	case strings.HasPrefix(path, "/tag/"):
		// install.sh only needs the URL it was redirected to; answer 200 so HEAD succeeds.
		fmt.Fprintf(w, "bnat %s\n", strings.TrimPrefix(path, "/tag/"))
	case strings.HasPrefix(path, "/download/"):
		parts := strings.Split(strings.TrimPrefix(path, "/download/"), "/")
		if len(parts) != 2 || !mirrorTagRe.MatchString(parts[0]) || !mirrorFileRe.MatchString(parts[1]) {
			http.NotFound(w, r)
			return
		}
		m.serveFile(w, r, parts[0], parts[1])
	default:
		http.NotFound(w, r)
	}
}

func (m *mirror) index(w http.ResponseWriter, r *http.Request) {
	tag, _ := m.latestTag(r.Context())
	if tag == "" {
		tag = "unknown"
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "bnat release mirror (latest: %s)\n\nInstall or update:\n\n  curl -fsSL %s/install.sh | sh\n\nFiles: %s/download/<tag>/<file>, same names as on GitHub.\n", tag, m.self, m.self)
}

// script returns install.sh set up to download from this mirror, falling back to GitHub.
func (m *mirror) script() string {
	var b strings.Builder
	for _, line := range strings.SplitAfter(bnat.InstallScript, "\n") {
		switch {
		case strings.Contains(line, "# bnat:primary"):
			fmt.Fprintf(&b, "\tprimary=\"${BNAT_DOWNLOAD_BASE:-%s}\" # bnat:primary\n", m.self)
		case strings.Contains(line, "# bnat:fallback"):
			fmt.Fprintf(&b, "\tfallback=\"${BNAT_FALLBACK_BASE-%s}\" # bnat:fallback\n", m.upstream)
		default:
			b.WriteString(strings.ReplaceAll(line, m.rawURL, m.self+"/install.sh"))
		}
	}
	return b.String()
}

// latestTag asks GitHub for the latest release at most every few minutes and
// remembers the answer, so the mirror keeps working when GitHub is down.
func (m *mirror) latestTag(ctx context.Context) (string, error) {
	m.mu.Lock()
	cached, fresh := m.latest, time.Since(m.checkedAt) < mirrorLatestTTL
	m.mu.Unlock()
	if cached != "" && fresh {
		return cached, nil
	}

	tag, err := m.fetchLatest(ctx)
	if err != nil {
		if cached != "" {
			m.log.Warn("can't check latest release, using cached", "tag", cached, "err", err)
			m.mu.Lock()
			m.checkedAt = time.Now() // don't hammer an unreachable upstream
			m.mu.Unlock()
			return cached, nil
		}
		return "", err
	}
	m.mu.Lock()
	changed := tag != m.latest
	m.latest, m.checkedAt = tag, time.Now()
	m.mu.Unlock()
	if changed {
		os.MkdirAll(m.dir, 0o755)
		os.WriteFile(filepath.Join(m.dir, "latest"), []byte(tag+"\n"), 0o644)
		m.log.Info("new release", "tag", tag)
		go m.prefetch(tag)
	}
	return tag, nil
}

func (m *mirror) fetchLatest(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, m.upstream+"/latest", nil)
	resp, err := m.client.Do(req)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	_, tag, ok := strings.Cut(resp.Header.Get("Location"), "/tag/")
	if !ok || !mirrorTagRe.MatchString(tag) {
		return "", fmt.Errorf("unexpected answer from %s/latest: HTTP %d", m.upstream, resp.StatusCode)
	}
	return tag, nil
}

// prefetch mirrors every file of a release listed in its checksums.txt.
func (m *mirror) prefetch(tag string) {
	path, err := m.ensure(context.Background(), tag, "checksums.txt")
	if err != nil {
		m.log.Warn("prefetch failed", "tag", tag, "err", err)
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 || !mirrorFileRe.MatchString(f[1]) {
			continue
		}
		if _, err := m.ensure(context.Background(), tag, f[1]); err != nil {
			m.log.Warn("prefetch failed", "tag", tag, "file", f[1], "err", err)
			continue
		}
		n++
	}
	m.log.Info("release mirrored", "tag", tag, "files", n)
	m.prune(tag)
}

// prune keeps the newest mirrorKeep releases (by when they were mirrored).
func (m *mirror) prune(current string) {
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return
	}
	type rel struct {
		name string
		mod  time.Time
	}
	var rels []rel
	for _, e := range entries {
		if !e.IsDir() || !mirrorTagRe.MatchString(e.Name()) || e.Name() == current {
			continue
		}
		if info, err := e.Info(); err == nil {
			rels = append(rels, rel{e.Name(), info.ModTime()})
		}
	}
	sort.Slice(rels, func(i, j int) bool { return rels[i].mod.After(rels[j].mod) })
	for i, r := range rels {
		if i >= mirrorKeep-1 {
			os.RemoveAll(filepath.Join(m.dir, r.name))
			m.log.Info("pruned old release", "tag", r.name)
		}
	}
}

func (m *mirror) serveFile(w http.ResponseWriter, r *http.Request, tag, file string) {
	path, err := m.ensure(r.Context(), tag, file)
	if err != nil {
		if errors.Is(err, errUpstreamNotFound) {
			http.NotFound(w, r)
			return
		}
		m.log.Warn("mirror fetch failed", "tag", tag, "file", file, "err", err)
		http.Error(w, "not mirrored yet and upstream unreachable", http.StatusBadGateway)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	if strings.HasSuffix(file, ".txt") {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	http.ServeFile(w, r, path)
}

var errUpstreamNotFound = errors.New("not found upstream")

// ensure returns the local path of a release file, downloading it once.
// Release files never change, so a cached copy is served forever.
func (m *mirror) ensure(ctx context.Context, tag, file string) (string, error) {
	path := filepath.Join(m.dir, tag, file)
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}

	key := tag + "/" + file
	m.mu.Lock()
	lock := m.fetching[key]
	if lock == nil {
		lock = &sync.Mutex{}
		m.fetching[key] = lock
	}
	m.mu.Unlock()
	lock.Lock()
	defer lock.Unlock()
	if _, err := os.Stat(path); err == nil {
		return path, nil // fetched by a concurrent request
	}

	// Detach from the client: a dropped request shouldn't waste a half-done download.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Minute)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, m.upstream+"/download/"+tag+"/"+file, nil)
	resp, err := m.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return "", errUpstreamNotFound
	case resp.StatusCode != http.StatusOK:
		return "", fmt.Errorf("upstream HTTP %d", resp.StatusCode)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+file+".*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, mirrorMaxFile+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	switch {
	case err != nil:
		return "", err
	case n > mirrorMaxFile:
		return "", errors.New("file too large")
	case resp.ContentLength >= 0 && n != resp.ContentLength:
		return "", fmt.Errorf("short download: %d of %d bytes", n, resp.ContentLength)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return "", err
	}
	m.log.Info("mirrored", "file", key, "bytes", n)
	return path, nil
}

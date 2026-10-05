package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/bcrypt"

	"github.com/Suro4ek/bnat/internal/proto"
)

type Config struct {
	Domain        string // admin + base for http tunnels: bnat.example.com
	TCPHost       string // hostname shown for tcp/ssh tunnels: tun.bnat.example.com
	HTTPAddr      string // :80
	HTTPSAddr     string // :443
	TLS           bool   // obtain certificates via Let's Encrypt
	ACMEEmail     string
	PublicScheme  string // scheme used in printed URLs; derived from TLS when empty
	DataDir       string
	AdminPassword string
	TCPBind       string // address tcp tunnel listeners bind to
	PortMin       int
	PortMax       int
	// TrustedProxies are reverse proxies in front of bnat whose
	// X-Forwarded-For/Proto/Host headers are believed.
	TrustedProxies []netip.Prefix
	// ReleasesHost, if set, serves install.sh and mirrored bnat releases
	// (for clients that can't reach GitHub), e.g. release.bnat.example.com.
	ReleasesHost string
	// ReleasesUpstream is where releases are mirrored from.
	ReleasesUpstream string // default https://github.com/Suro4ek/bnat/releases
}

type Server struct {
	cfg   Config
	store *Store
	log   *slog.Logger

	mu       sync.RWMutex
	tunnels  map[string]*tunnel
	sessions map[*agentSession]struct{}

	adminHandler http.Handler
	mirror       *mirror // nil unless ReleasesHost is set
	pairLimit    limiter
}

type agentSession struct {
	id        string
	token     Token
	remote    string
	hostname  string
	user      string
	mux       *yamux.Session
	connected time.Time

	ctrlMu sync.Mutex
	ctrl   *json.Encoder

	tunnels []*tunnel
}

func (a *agentSession) send(m proto.ServerMsg) error {
	a.ctrlMu.Lock()
	defer a.ctrlMu.Unlock()
	return a.ctrl.Encode(m)
}

type tunnel struct {
	name       string
	typ        string
	embedded   bool
	local      string
	hostHeader string
	sess       *agentSession
	port       int
	ln         net.Listener
	transport  *http.Transport
	created    time.Time

	conns    atomic.Int64
	active   atomic.Int64
	bytesIn  atomic.Int64 // from public clients
	bytesOut atomic.Int64 // to public clients
}

// open opens a new stream to the agent for this tunnel.
func (t *tunnel) open(remote string) (net.Conn, error) {
	st, err := t.sess.mux.OpenStream()
	if err != nil {
		return nil, err
	}
	if err := proto.WriteHeader(st, proto.StreamHeader{Tunnel: t.name, Remote: remote}); err != nil {
		st.Close()
		return nil, err
	}
	t.conns.Add(1)
	return &proto.CountingConn{Conn: st, In: &t.bytesOut, Out: &t.bytesIn}, nil
}

func New(cfg Config) (*Server, error) {
	if cfg.Domain == "" {
		return nil, errors.New("domain is required")
	}
	cfg.Domain = strings.ToLower(cfg.Domain)
	if cfg.TCPHost == "" {
		cfg.TCPHost = cfg.Domain
	}
	if cfg.PublicScheme == "" {
		cfg.PublicScheme = "http"
		if cfg.TLS {
			cfg.PublicScheme = "https"
		}
	}
	if cfg.PortMin <= 0 || cfg.PortMax < cfg.PortMin {
		return nil, fmt.Errorf("bad port range %d-%d", cfg.PortMin, cfg.PortMax)
	}
	st, err := OpenStore(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:      cfg,
		store:    st,
		log:      slog.Default(),
		tunnels:  map[string]*tunnel{},
		sessions: map[*agentSession]struct{}{},
	}
	if err := s.initAdminPassword(); err != nil {
		return nil, err
	}
	s.adminHandler = s.admin()
	if cfg.ReleasesHost != "" {
		s.cfg.ReleasesHost = strings.ToLower(cfg.ReleasesHost)
		if s.cfg.ReleasesUpstream == "" {
			s.cfg.ReleasesUpstream = "https://github.com/Suro4ek/bnat/releases"
		}
		s.mirror = newMirror(s.cfg.PublicScheme+"://"+s.cfg.ReleasesHost+s.publicPort(), s.cfg.ReleasesUpstream, filepath.Join(cfg.DataDir, "releases"), s.log)
	}
	return s, nil
}

func (s *Server) initAdminPassword() error {
	if s.cfg.AdminPassword != "" {
		return nil
	}
	if s.store.AdminPassHash() != "" {
		return nil
	}
	pass := randHex(10)
	h, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if err := s.store.SetAdminPassHash(string(h)); err != nil {
		return err
	}
	s.log.Warn("generated admin password (shown only once; set --admin-password to override)", "password", pass)
	return nil
}

func (s *Server) checkAdminPassword(p string) bool {
	if s.cfg.AdminPassword != "" {
		return subtleEq(p, s.cfg.AdminPassword)
	}
	return bcrypt.CompareHashAndPassword([]byte(s.store.AdminPassHash()), []byte(p)) == nil
}

// Run serves until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	errc := make(chan error, 2)
	var servers []*http.Server
	newSrv := func(addr string, h http.Handler) *http.Server {
		srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 15 * time.Second, ErrorLog: slog.NewLogLogger(s.log.Handler(), slog.LevelDebug)}
		servers = append(servers, srv)
		return srv
	}

	if s.cfg.TLS {
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(filepath.Join(s.cfg.DataDir, "certs")),
			HostPolicy: s.hostPolicy,
			Email:      s.cfg.ACMEEmail,
		}
		https := newSrv(s.cfg.HTTPSAddr, s)
		https.TLSConfig = m.TLSConfig()
		https.TLSConfig.MinVersion = tls.VersionTLS12
		redirect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://"+stripPort(r.Host)+r.URL.RequestURI(), http.StatusMovedPermanently)
		})
		http80 := newSrv(s.cfg.HTTPAddr, m.HTTPHandler(redirect))
		go func() { errc <- fmt.Errorf("https: %w", https.ListenAndServeTLS("", "")) }()
		go func() { errc <- fmt.Errorf("http: %w", http80.ListenAndServe()) }()
		s.log.Info("listening", "https", s.cfg.HTTPSAddr, "http", s.cfg.HTTPAddr)
	} else {
		srv := newSrv(s.cfg.HTTPAddr, s)
		go func() { errc <- fmt.Errorf("http: %w", srv.ListenAndServe()) }()
		s.log.Info("listening", "http", s.cfg.HTTPAddr)
	}
	s.log.Info("admin panel", "url", s.adminURL())

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, srv := range servers {
		srv.Shutdown(sctx)
	}
	s.mu.Lock()
	for a := range s.sessions {
		a.mux.Close()
	}
	s.mu.Unlock()
	return nil
}

// hostPolicy limits certificate issuance to hosts we actually serve, so random
// subdomains can't burn through Let's Encrypt rate limits.
func (s *Server) hostPolicy(_ context.Context, host string) error {
	host = strings.ToLower(host)
	if host == s.cfg.Domain || (s.mirror != nil && host == s.cfg.ReleasesHost) {
		return nil
	}
	if name, ok := s.subdomain(host); ok {
		if r, ok := s.store.Reservation(name); ok && r.Type == proto.TypeHTTP {
			return nil
		}
	}
	if d, ok := s.store.Domain(host); ok && d.Verified {
		return nil
	}
	return fmt.Errorf("host %q not allowed", host)
}

func (s *Server) subdomain(host string) (string, bool) {
	name, ok := strings.CutSuffix(host, "."+s.cfg.Domain)
	if !ok || !proto.ValidName(name) {
		return "", false
	}
	return name, true
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(stripPort(r.Host))
	if s.mirror != nil && host == s.cfg.ReleasesHost {
		s.mirror.ServeHTTP(w, r)
		return
	}
	if host == s.cfg.Domain {
		if !s.serveAgentAPI(w, r) {
			s.adminHandler.ServeHTTP(w, r)
		}
		return
	}
	if name, ok := s.subdomain(host); ok {
		s.proxyHTTP(w, r, name)
		return
	}
	if d, ok := s.store.Domain(host); ok && d.Verified {
		s.proxyHTTP(w, r, d.Tunnel)
		return
	}
	// Agents may also reach us by IP or an internal name (e.g. a docker
	// service name); tunnel hosts are matched above, so nothing is shadowed.
	if s.serveAgentAPI(w, r) {
		return
	}
	http.Error(w, "bnat: unknown host "+host, http.StatusNotFound)
}

func (s *Server) serveAgentAPI(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case proto.AgentPath:
		s.handleAgent(w, r)
	case proto.PairPath:
		s.handlePair(w, r)
	default:
		return false
	}
	return true
}

func (s *Server) proxyHTTP(w http.ResponseWriter, r *http.Request, name string) {
	s.mu.RLock()
	t := s.tunnels[name]
	s.mu.RUnlock()
	if t == nil || t.typ != proto.TypeHTTP {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintf(w, "bnat: tunnel %q is offline\n", name)
		return
	}
	t.active.Add(1)
	defer t.active.Add(-1)
	rp := &httputil.ReverseProxy{
		Transport:     t.transport,
		FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			s.setForwarded(pr)
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = t.name
			pr.Out.Host = pr.In.Host
			if t.hostHeader != "" {
				pr.Out.Host = t.hostHeader
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			s.log.Debug("proxy error", "tunnel", t.name, "err", err)
			http.Error(w, "bnat: upstream error: "+err.Error(), http.StatusBadGateway)
		},
	}
	rp.ServeHTTP(w, r)
}

func (s *Server) handleAgent(w http.ResponseWriter, r *http.Request) {
	plain, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	tok, ok := s.store.Authenticate(plain)
	if !ok {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	wc, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	nc := websocket.NetConn(context.Background(), wc, websocket.MessageBinary)
	mux, err := yamux.Server(nc, proto.YamuxConfig())
	if err != nil {
		nc.Close()
		return
	}
	defer mux.Close()

	ctrlc := make(chan net.Conn, 1)
	go func() {
		st, err := mux.AcceptStream()
		if err == nil {
			ctrlc <- st
		}
	}()
	var ctrl net.Conn
	select {
	case ctrl = <-ctrlc:
	case <-time.After(15 * time.Second):
		return
	}
	var hello proto.Hello
	if err := json.NewDecoder(ctrl).Decode(&hello); err != nil {
		return
	}

	a := &agentSession{
		id:        randHex(4),
		token:     tok,
		remote:    s.clientIP(r),
		hostname:  hello.Hostname,
		user:      hello.User,
		mux:       mux,
		connected: time.Now(),
		ctrl:      json.NewEncoder(ctrl),
	}
	log := s.log.With("agent", a.id, "token", tok.Name, "remote", a.remote, "host", a.hostname)

	s.mu.Lock()
	s.sessions[a] = struct{}{}
	s.mu.Unlock()
	defer s.dropSession(a)

	s.evictStale(hello.Tunnels, log)

	var infos []proto.TunnelInfo
	for _, req := range hello.Tunnels {
		info := s.register(a, req)
		if info.Error != "" {
			log.Warn("tunnel rejected", "name", req.Name, "type", req.Type, "err", info.Error)
		} else {
			log.Info("tunnel up", "name", info.Name, "type", info.Type, "url", info.URL, "port", info.Port)
		}
		infos = append(infos, info)
	}
	if err := a.send(proto.ServerMsg{Type: proto.MsgWelcome, Tunnels: infos}); err != nil {
		return
	}
	s.sendKeys(a)

	// Nothing else is accepted from the agent; wait for it to go away.
	<-mux.CloseChan()
	log.Info("agent disconnected")
}

func (s *Server) handlePair(w http.ResponseWriter, r *http.Request) {
	reply := func(code int, resp proto.PairResponse) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(resp)
	}
	if r.Method != http.MethodPost {
		reply(http.StatusMethodNotAllowed, proto.PairResponse{Error: "POST required"})
		return
	}
	ip := s.clientIP(r)
	if !s.pairLimit.allow(ip) {
		reply(http.StatusTooManyRequests, proto.PairResponse{Error: "too many attempts, try again later"})
		return
	}
	var req proto.PairRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		reply(http.StatusBadRequest, proto.PairResponse{Error: "bad request"})
		return
	}
	t, plain, err := s.store.Pair(req.Code, req.Hostname, req.User)
	if err != nil {
		s.pairLimit.fail(ip)
		s.log.Warn("pairing failed", "remote", ip, "host", req.Hostname)
		reply(http.StatusForbidden, proto.PairResponse{Error: err.Error()})
		return
	}
	// A re-paired client's old token is gone; drop agents still using it.
	s.kickToken(t.ID)
	s.log.Info("client paired", "client", t.Name, "remote", ip, "machine", req.User+"@"+req.Hostname)
	reply(http.StatusOK, proto.PairResponse{Token: plain, Name: t.Name})
}

// limiter counts failed attempts per IP in a sliding-ish window.
type limiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

const (
	pairMaxFails = 10
	pairWindow   = 10 * time.Minute
)

func (l *limiter) recent(ip string) []time.Time {
	cut := time.Now().Add(-pairWindow)
	h := slices.DeleteFunc(l.hits[ip], func(t time.Time) bool { return t.Before(cut) })
	if len(h) == 0 {
		delete(l.hits, ip)
	} else {
		l.hits[ip] = h
	}
	return h
}

func (l *limiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recent(ip)) < pairMaxFails
}

func (l *limiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.hits == nil {
		l.hits = map[string][]time.Time{}
	}
	l.hits[ip] = append(l.recent(ip), time.Now())
}

func (s *Server) register(a *agentSession, req proto.TunnelReq) proto.TunnelInfo {
	info := proto.TunnelInfo{Name: req.Name, Type: req.Type}
	fail := func(f string, args ...any) proto.TunnelInfo {
		info.Error = fmt.Sprintf(f, args...)
		return info
	}
	if req.Type != proto.TypeHTTP && req.Type != proto.TypeTCP && req.Type != proto.TypeSSH {
		return fail("unknown tunnel type %q", req.Type)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if req.Name == "" {
		for {
			req.Name = randHex(4)
			if _, ok := s.store.Reservation(req.Name); !ok && s.tunnels[req.Name] == nil {
				break
			}
		}
		info.Name = req.Name
	}
	if !proto.ValidName(req.Name) {
		return fail("invalid name %q: use a-z, 0-9 and '-'", req.Name)
	}
	if s.mirror != nil && req.Name+"."+s.cfg.Domain == s.cfg.ReleasesHost {
		return fail("name %q is reserved for the release mirror", req.Name)
	}
	if s.tunnels[req.Name] != nil {
		return fail("tunnel %q is already connected", req.Name)
	}
	res, reserved := s.store.Reservation(req.Name)
	if reserved && res.Type != req.Type {
		return fail("name %q is reserved for a %s tunnel (release it in the admin panel)", req.Name, res.Type)
	}

	t := &tunnel{
		name:       req.Name,
		typ:        req.Type,
		embedded:   req.Embedded,
		local:      req.Local,
		hostHeader: req.HostHeader,
		sess:       a,
		created:    time.Now(),
	}
	res = Reservation{Name: req.Name, Type: req.Type, Port: res.Port, LastSeen: time.Now()}

	switch req.Type {
	case proto.TypeHTTP:
		t.transport = &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return t.open("")
			},
			MaxIdleConnsPerHost: 32,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  true,
		}
		info.URL = s.httpURL(req.Name)
	default:
		ln, port, err := s.listenTCP(res.Port)
		if err != nil {
			return fail("allocate port: %v", err)
		}
		t.ln, t.port, res.Port = ln, port, port
		info.Host, info.Port = s.cfg.TCPHost, port
		go s.serveTCP(t)
	}
	if err := s.store.PutReservation(res); err != nil {
		s.log.Error("save reservation", "err", err)
	}
	s.tunnels[t.name] = t
	a.tunnels = append(a.tunnels, t)
	return info
}

// listenTCP binds the preferred port if possible, otherwise a random free one
// that is not reserved by another tunnel.
func (s *Server) listenTCP(preferred int) (net.Listener, int, error) {
	if preferred > 0 {
		if ln, err := net.Listen("tcp", net.JoinHostPort(s.cfg.TCPBind, strconv.Itoa(preferred))); err == nil {
			return ln, preferred, nil
		}
	}
	span := s.cfg.PortMax - s.cfg.PortMin + 1
	for range 200 {
		p := s.cfg.PortMin + rand.IntN(span)
		if s.store.PortInUse(p) {
			continue
		}
		if ln, err := net.Listen("tcp", net.JoinHostPort(s.cfg.TCPBind, strconv.Itoa(p))); err == nil {
			return ln, p, nil
		}
	}
	return nil, 0, errors.New("no free port in range")
}

func (s *Server) serveTCP(t *tunnel) {
	for {
		c, err := t.ln.Accept()
		if err != nil {
			return
		}
		go func() {
			t.active.Add(1)
			defer t.active.Add(-1)
			st, err := t.open(c.RemoteAddr().String())
			if err != nil {
				c.Close()
				return
			}
			proto.Join(c, st)
		}()
	}
}

// stalePingTimeout is how long an agent holding a requested tunnel name has
// to answer a ping before it is considered dead and replaced.
const stalePingTimeout = 5 * time.Second

// evictStale handles agents that come back before the server noticed their
// old connection died (network drop, IP change, reboot): if a requested name
// is held by a session that no longer answers pings, that session is closed
// so the name can be taken over immediately instead of after keepalive
// timeouts. Live sessions are left alone, so two running agents can't keep
// kicking each other off.
func (s *Server) evictStale(reqs []proto.TunnelReq, log *slog.Logger) {
	holders := map[*agentSession]bool{}
	s.mu.RLock()
	for _, req := range reqs {
		if t := s.tunnels[req.Name]; t != nil {
			holders[t.sess] = true
		}
	}
	s.mu.RUnlock()

	var wg sync.WaitGroup
	for old := range holders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if alive(old.mux, stalePingTimeout) {
				return
			}
			log.Info("replacing unresponsive agent", "old_agent", old.id, "old_remote", old.remote)
			old.mux.Close()
			s.dropSession(old) // free names and ports now; its handler will find nothing left
		}()
	}
	wg.Wait()
}

func alive(mux *yamux.Session, timeout time.Duration) bool {
	res := make(chan error, 1)
	go func() {
		_, err := mux.Ping()
		res <- err
	}()
	select {
	case err := <-res:
		return err == nil
	case <-time.After(timeout):
		return false
	}
}

func (s *Server) dropSession(a *agentSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, a)
	for _, t := range a.tunnels {
		if s.tunnels[t.name] == t {
			delete(s.tunnels, t.name)
		}
		if t.ln != nil {
			t.ln.Close()
		}
		if t.transport != nil {
			t.transport.CloseIdleConnections()
		}
		if r, ok := s.store.Reservation(t.name); ok {
			r.LastSeen = time.Now()
			s.store.PutReservation(r)
		}
	}
}

func (s *Server) sendKeys(a *agentSession) {
	keys := map[string][]string{}
	for _, t := range a.tunnels {
		if t.typ == proto.TypeSSH && t.embedded {
			keys[t.name] = s.store.KeysFor(t.name)
		}
	}
	if len(keys) > 0 {
		a.send(proto.ServerMsg{Type: proto.MsgKeys, Keys: keys})
	}
}

// pushKeys sends updated authorized keys to every connected agent.
func (s *Server) pushKeys() {
	s.mu.RLock()
	sessions := make([]*agentSession, 0, len(s.sessions))
	for a := range s.sessions {
		sessions = append(sessions, a)
	}
	s.mu.RUnlock()
	for _, a := range sessions {
		go s.sendKeys(a)
	}
}

// onlineClients returns the number of connected agents per client ID.
func (s *Server) onlineClients() map[string]int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := map[string]int{}
	for a := range s.sessions {
		m[a.token.ID]++
	}
	return m
}

// kickToken disconnects all agents using the given token.
func (s *Server) kickToken(id string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for a := range s.sessions {
		if a.token.ID == id {
			a.mux.Close()
		}
	}
}

func (s *Server) kickTunnel(name string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if t := s.tunnels[name]; t != nil {
		t.sess.mux.Close()
	}
}

func (s *Server) httpURL(name string) string {
	return s.cfg.PublicScheme + "://" + name + "." + s.cfg.Domain + s.publicPort()
}

func (s *Server) adminURL() string {
	return s.cfg.PublicScheme + "://" + s.cfg.Domain + s.publicPort()
}

// publicPort returns ":port" when the plain-HTTP listener is on a
// non-standard port (local development), otherwise "".
func (s *Server) publicPort() string {
	if s.cfg.TLS || s.cfg.PublicScheme == "https" {
		return ""
	}
	_, port, _ := net.SplitHostPort(s.cfg.HTTPAddr)
	if port == "" || port == "80" {
		return ""
	}
	return ":" + port
}

type tunnelView struct {
	Name, Type, Public, Local, Agent, AgentIP, Token string
	Embedded                                         bool
	Since                                            time.Time
	Conns, Active, BytesIn, BytesOut                 int64
	Port                                             int
	SSHCommand                                       string
}

func (s *Server) tunnelViews() []tunnelView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]tunnelView, 0, len(s.tunnels))
	for _, t := range s.tunnels {
		v := tunnelView{
			Name: t.name, Type: t.typ, Local: t.local, Embedded: t.embedded,
			Agent: t.sess.user + "@" + t.sess.hostname, AgentIP: t.sess.remote, Token: t.sess.token.Name,
			Since: t.created, Conns: t.conns.Load(), Active: t.active.Load(),
			BytesIn: t.bytesIn.Load(), BytesOut: t.bytesOut.Load(), Port: t.port,
		}
		if t.typ == proto.TypeHTTP {
			v.Public = s.httpURL(t.name)
		} else {
			v.Public = net.JoinHostPort(s.cfg.TCPHost, strconv.Itoa(t.port))
		}
		if t.typ == proto.TypeSSH {
			v.SSHCommand = fmt.Sprintf("ssh -p %d %s@%s", t.port, t.sess.user, s.cfg.TCPHost)
		}
		out = append(out, v)
	}
	slices.SortFunc(out, func(a, b tunnelView) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// verifyDomain checks that host points at us via CNAME or resolves to the
// same addresses as the main domain (for apex domains with CNAME flattening).
func (s *Server) verifyDomain(ctx context.Context, host string) error {
	var res net.Resolver
	if cname, err := res.LookupCNAME(ctx, host); err == nil {
		cname = strings.ToLower(strings.TrimSuffix(cname, "."))
		if cname == s.cfg.Domain || strings.HasSuffix(cname, "."+s.cfg.Domain) {
			return nil
		}
	}
	want, err := res.LookupHost(ctx, s.cfg.Domain)
	if err != nil {
		return fmt.Errorf("resolve %s: %v", s.cfg.Domain, err)
	}
	got, err := res.LookupHost(ctx, host)
	if err != nil {
		return fmt.Errorf("resolve %s: %v", host, err)
	}
	for _, g := range got {
		if slices.Contains(want, g) {
			return nil
		}
	}
	return fmt.Errorf("%s does not point to %s (add CNAME %s → %s)", host, s.cfg.Domain, host, s.cfg.Domain)
}

func stripPort(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

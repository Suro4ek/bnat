package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/suro/bnat/internal/proto"
)

//go:embed templates/*.html
var templateFS embed.FS

const sessionCookie = "bnat_session"

var (
	pagesOnce sync.Once
	pages     map[string]*template.Template
)

func loadPages() map[string]*template.Template {
	pagesOnce.Do(func() {
		funcs := template.FuncMap{
			"bytes": humanBytes,
			"ago":   ago,
			"join":  strings.Join,
		}
		pages = map[string]*template.Template{}
		for _, p := range []string{"login", "tunnels", "clients", "keys", "domains"} {
			pages[p] = template.Must(template.New("").Funcs(funcs).ParseFS(templateFS, "templates/layout.html", "templates/"+p+".html"))
		}
	})
	return pages
}

func (s *Server) admin() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginSubmit)
	mux.HandleFunc("POST /logout", s.logout)

	auth := func(h http.HandlerFunc) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !s.authed(r) {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			if r.Method == http.MethodPost && !sameOrigin(r) {
				http.Error(w, "cross-origin request rejected", http.StatusForbidden)
				return
			}
			h(w, r)
		})
	}
	mux.Handle("GET /{$}", auth(s.tunnelsPage))
	mux.Handle("POST /tunnels/kick", auth(s.tunnelKick))
	mux.Handle("POST /reservations/delete", auth(s.reservationDelete))
	mux.Handle("GET /clients", auth(s.clientsPage))
	mux.Handle("POST /clients", auth(s.clientCreate))
	mux.Handle("POST /clients/code", auth(s.clientNewCode))
	mux.Handle("POST /clients/delete", auth(s.clientDelete))
	mux.Handle("GET /keys", auth(s.keysPage))
	mux.Handle("POST /keys", auth(s.keyCreate))
	mux.Handle("POST /keys/delete", auth(s.keyDelete))
	mux.Handle("GET /domains", auth(s.domainsPage))
	mux.Handle("POST /domains", auth(s.domainCreate))
	mux.Handle("POST /domains/verify", auth(s.domainVerify))
	mux.Handle("POST /domains/delete", auth(s.domainDelete))
	return mux
}

type pageData struct {
	Page    string
	Title   string
	Domain  string
	Error   string
	Flash   string
	Data    any
	TCPHost string
	Admin   string
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, page string, data any) {
	d := pageData{
		Page:    page,
		Domain:  s.cfg.Domain,
		TCPHost: s.cfg.TCPHost,
		Admin:   s.adminURL(),
		Data:    data,
		Error:   r.URL.Query().Get("err"),
		Flash:   r.URL.Query().Get("ok"),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Frame-Options", "DENY")
	if err := loadPages()[page].ExecuteTemplate(w, "layout", d); err != nil {
		s.log.Error("render", "page", page, "err", err)
	}
}

func back(w http.ResponseWriter, r *http.Request, path string, err error, ok string) {
	q := url.Values{}
	if err != nil {
		q.Set("err", err.Error())
	} else if ok != "" {
		q.Set("ok", ok)
	}
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	http.Redirect(w, r, path, http.StatusSeeOther)
}

// ---- auth ----

func (s *Server) sign(v string) string {
	m := hmac.New(sha256.New, s.store.Secret())
	m.Write([]byte(v))
	return hex.EncodeToString(m.Sum(nil))
}

func (s *Server) authed(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	exp, sig, ok := strings.Cut(c.Value, ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(s.sign(exp))) {
		return false
	}
	n, err := strconv.ParseInt(exp, 10, 64)
	return err == nil && time.Now().Unix() < n
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "login", nil)
}

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminPassword(r.FormValue("password")) {
		time.Sleep(time.Second)
		back(w, r, "/login", fmt.Errorf("wrong password"), "")
		return
	}
	exp := strconv.FormatInt(time.Now().Add(7*24*time.Hour).Unix(), 10)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    exp + "." + s.sign(exp),
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.PublicScheme == "https",
		SameSite: http.SameSiteStrictMode,
		MaxAge:   7 * 24 * 3600,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true // SameSite=Strict already keeps the cookie off cross-site requests
	}
	u, err := url.Parse(o)
	return err == nil && strings.EqualFold(u.Host, r.Host)
}

func subtleEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ---- tunnels ----

func (s *Server) tunnelsPage(w http.ResponseWriter, r *http.Request) {
	active := s.tunnelViews()
	online := map[string]bool{}
	for _, t := range active {
		online[t.Name] = true
	}
	type resView struct {
		Reservation
		Online bool
		Public string
	}
	var res []resView
	for _, x := range s.store.Reservations() {
		v := resView{Reservation: x, Online: online[x.Name]}
		if x.Type == proto.TypeHTTP {
			v.Public = s.httpURL(x.Name)
		} else {
			v.Public = fmt.Sprintf("%s:%d", s.cfg.TCPHost, x.Port)
		}
		res = append(res, v)
	}
	s.render(w, r, "tunnels", map[string]any{"Active": active, "Reservations": res})
}

func (s *Server) tunnelKick(w http.ResponseWriter, r *http.Request) {
	s.kickTunnel(r.FormValue("name"))
	back(w, r, "/", nil, "agent disconnected")
}

func (s *Server) reservationDelete(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	s.mu.RLock()
	online := s.tunnels[name] != nil
	s.mu.RUnlock()
	if online {
		back(w, r, "/", fmt.Errorf("tunnel %s is online; disconnect it first", name), "")
		return
	}
	back(w, r, "/", s.store.DeleteReservation(name), "released "+name)
}

// ---- clients ----

func (s *Server) clientsPage(w http.ResponseWriter, r *http.Request) {
	s.renderClients(w, r, nil)
}

// renderClients shows the client list, optionally with a freshly issued code.
func (s *Server) renderClients(w http.ResponseWriter, r *http.Request, code map[string]any) {
	s.render(w, r, "clients", map[string]any{
		"Clients": s.store.Tokens(),
		"Online":  s.onlineClients(),
		"Code":    code,
	})
}

func (s *Server) showCode(w http.ResponseWriter, r *http.Request, name, code string) {
	s.renderClients(w, r, map[string]any{
		"Name":    name,
		"Code":    code,
		"Minutes": int(PairCodeTTL.Minutes()),
		"Login":   fmt.Sprintf("bnat login %s %s", s.adminURL(), code),
	})
}

func (s *Server) clientCreate(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		back(w, r, "/clients", fmt.Errorf("name is required"), "")
		return
	}
	code, err := s.store.CreateClient(name)
	if err != nil {
		back(w, r, "/clients", err, "")
		return
	}
	s.showCode(w, r, name, code)
}

func (s *Server) clientNewCode(w http.ResponseWriter, r *http.Request) {
	t, code, err := s.store.NewPairCode(r.FormValue("id"))
	if err != nil {
		back(w, r, "/clients", err, "")
		return
	}
	s.showCode(w, r, t.Name, code)
}

func (s *Server) clientDelete(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	err := s.store.DeleteToken(id)
	if err == nil {
		s.kickToken(id)
	}
	back(w, r, "/clients", err, "client removed")
}

// ---- ssh keys ----

func (s *Server) keysPage(w http.ResponseWriter, r *http.Request) {
	var sshTunnels []string
	for _, x := range s.store.Reservations() {
		if x.Type == proto.TypeSSH {
			sshTunnels = append(sshTunnels, x.Name)
		}
	}
	s.render(w, r, "keys", map[string]any{"Keys": s.store.Keys(), "SSHTunnels": sshTunnels})
}

func (s *Server) keyCreate(w http.ResponseWriter, r *http.Request) {
	var tunnels []string
	for _, t := range strings.FieldsFunc(r.FormValue("tunnels"), func(c rune) bool { return c == ',' || c == ' ' }) {
		if !proto.ValidName(t) {
			back(w, r, "/keys", fmt.Errorf("invalid tunnel name %q", t), "")
			return
		}
		tunnels = append(tunnels, t)
	}
	err := s.store.AddKey(strings.TrimSpace(r.FormValue("name")), r.FormValue("key"), tunnels)
	if err == nil {
		s.pushKeys()
	}
	back(w, r, "/keys", err, "key added")
}

func (s *Server) keyDelete(w http.ResponseWriter, r *http.Request) {
	err := s.store.DeleteKey(r.FormValue("id"))
	if err == nil {
		s.pushKeys()
	}
	back(w, r, "/keys", err, "key removed")
}

// ---- domains ----

func (s *Server) domainsPage(w http.ResponseWriter, r *http.Request) {
	var httpTunnels []string
	for _, x := range s.store.Reservations() {
		if x.Type == proto.TypeHTTP {
			httpTunnels = append(httpTunnels, x.Name)
		}
	}
	s.render(w, r, "domains", map[string]any{"Domains": s.store.Domains(), "HTTPTunnels": httpTunnels})
}

func (s *Server) domainCreate(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.FormValue("host")), "."))
	tunnel := strings.TrimSpace(r.FormValue("tunnel"))
	switch {
	case host == "" || strings.ContainsAny(host, "/: ") || !strings.Contains(host, "."):
		back(w, r, "/domains", fmt.Errorf("invalid domain %q", host), "")
		return
	case host == s.cfg.Domain || strings.HasSuffix(host, "."+s.cfg.Domain):
		back(w, r, "/domains", fmt.Errorf("subdomains of %s are routed automatically", s.cfg.Domain), "")
		return
	case !proto.ValidName(tunnel):
		back(w, r, "/domains", fmt.Errorf("invalid tunnel name %q", tunnel), "")
		return
	}
	if err := s.store.AddDomain(host, tunnel); err != nil {
		back(w, r, "/domains", err, "")
		return
	}
	s.checkDomain(r.Context(), host)
	back(w, r, "/domains", nil, "domain added")
}

func (s *Server) checkDomain(ctx context.Context, host string) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	s.store.SetDomainStatus(host, s.verifyDomain(ctx, host))
}

func (s *Server) domainVerify(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	s.checkDomain(r.Context(), host)
	d, _ := s.store.Domain(host)
	if !d.Verified {
		back(w, r, "/domains", fmt.Errorf("%s", d.Error), "")
		return
	}
	back(w, r, "/domains", nil, host+" verified")
}

func (s *Server) domainDelete(w http.ResponseWriter, r *http.Request) {
	back(w, r, "/domains", s.store.DeleteDomain(r.FormValue("host")), "domain removed")
}

// ---- helpers ----

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

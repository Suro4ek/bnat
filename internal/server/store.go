package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Token is an agent client. It starts with a one-time pairing code; when an
// agent redeems the code it gets a long-lived token (only hashes are stored).
type Token struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Hash     string    `json:"hash,omitempty"`
	Created  time.Time `json:"created"`
	LastUsed time.Time `json:"last_used,omitzero"`

	PairCodeHash string    `json:"pair_code_hash,omitempty"`
	PairExpires  time.Time `json:"pair_expires,omitzero"`
	PairedAt     time.Time `json:"paired_at,omitzero"`
	Hostname     string    `json:"hostname,omitempty"`
	User         string    `json:"user,omitempty"`
}

// Paired reports whether an agent has redeemed a code for this client.
func (t Token) Paired() bool { return t.Hash != "" }

// PairPending reports whether an unexpired pairing code exists.
func (t Token) PairPending() bool { return t.PairCodeHash != "" && time.Now().Before(t.PairExpires) }

type SSHKey struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Key         string    `json:"key"`
	Fingerprint string    `json:"fingerprint"`
	Tunnels     []string  `json:"tunnels,omitempty"` // empty = all ssh tunnels
	Created     time.Time `json:"created"`
}

type Domain struct {
	Host      string    `json:"host"`
	Tunnel    string    `json:"tunnel"`
	Verified  bool      `json:"verified"`
	Error     string    `json:"error,omitempty"`
	CheckedAt time.Time `json:"checked_at,omitzero"`
	Created   time.Time `json:"created"`
}

// Reservation pins a tunnel name to a type (and a port for tcp/ssh), so the
// address stays the same across reconnects.
type Reservation struct {
	Name     string    `json:"name"`
	Type     string    `json:"type"`
	Port     int       `json:"port,omitempty"`
	LastSeen time.Time `json:"last_seen"`
}

type data struct {
	Secret        string                  `json:"secret"`
	AdminPassHash string                  `json:"admin_pass_hash,omitempty"`
	Tokens        []*Token                `json:"tokens"`
	Keys          []*SSHKey               `json:"keys"`
	Domains       []*Domain               `json:"domains"`
	Reservations  map[string]*Reservation `json:"reservations"`
}

// Store is a small JSON-file database. All methods are safe for concurrent use.
type Store struct {
	path string
	mu   sync.Mutex
	d    data
}

func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dir, "bnat.json")}
	b, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(b, &s.d); err != nil {
			return nil, fmt.Errorf("parse %s: %w", s.path, err)
		}
	}
	if s.d.Reservations == nil {
		s.d.Reservations = map[string]*Reservation{}
	}
	if s.d.Secret == "" {
		s.d.Secret = randHex(32)
	}
	return s, s.save()
}

func (s *Store) save() error {
	b, err := json.MarshalIndent(&s.d, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) update(fn func(d *data) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(&s.d); err != nil {
		return err
	}
	return s.save()
}

func (s *Store) Secret() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return []byte(s.d.Secret)
}

func (s *Store) AdminPassHash() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.d.AdminPassHash
}

func (s *Store) SetAdminPassHash(h string) error {
	return s.update(func(d *data) error { d.AdminPassHash = h; return nil })
}

// ---- tokens ----

func hashToken(v string) string {
	h := sha256.Sum256([]byte(v))
	return hex.EncodeToString(h[:])
}

const PairCodeTTL = 15 * time.Minute

// pairAlphabet omits look-alike characters (0/O, 1/I/L).
const pairAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

func newPairCode() string {
	b := make([]byte, 8)
	rand.Read(b)
	for i := range b {
		b[i] = pairAlphabet[int(b[i])%len(pairAlphabet)]
	}
	return string(b[:4]) + "-" + string(b[4:])
}

// NormalizePairCode makes codes case- and separator-insensitive.
func NormalizePairCode(c string) string {
	c = strings.ToUpper(c)
	return strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' {
			return -1
		}
		return r
	}, c)
}

// CreateClient adds a client and returns its pairing code.
func (s *Store) CreateClient(name string) (string, error) {
	code := newPairCode()
	err := s.update(func(d *data) error {
		d.Tokens = append(d.Tokens, &Token{
			ID: randHex(6), Name: name, Created: time.Now(),
			PairCodeHash: hashToken(NormalizePairCode(code)), PairExpires: time.Now().Add(PairCodeTTL),
		})
		return nil
	})
	return code, err
}

// NewPairCode issues a fresh code for an existing client. Its current token
// keeps working until the code is redeemed.
func (s *Store) NewPairCode(id string) (Token, string, error) {
	code := newPairCode()
	var out Token
	err := s.update(func(d *data) error {
		for _, t := range d.Tokens {
			if t.ID == id {
				t.PairCodeHash = hashToken(NormalizePairCode(code))
				t.PairExpires = time.Now().Add(PairCodeTTL)
				out = *t
				return nil
			}
		}
		return errors.New("client not found")
	})
	return out, code, err
}

var ErrBadPairCode = errors.New("invalid or expired pairing code")

// Pair redeems a pairing code and returns the client's new plaintext token.
// Any previous token of that client stops working.
func (s *Store) Pair(code, hostname, user string) (Token, string, error) {
	h := hashToken(NormalizePairCode(code))
	plain := "bnat_" + randHex(24)
	var out Token
	err := s.update(func(d *data) error {
		for _, t := range d.Tokens {
			if t.PairCodeHash == h && time.Now().Before(t.PairExpires) {
				t.Hash = hashToken(plain)
				t.PairCodeHash, t.PairExpires = "", time.Time{}
				t.PairedAt, t.Hostname, t.User = time.Now(), hostname, user
				out = *t
				return nil
			}
		}
		return ErrBadPairCode
	})
	return out, plain, err
}

func (s *Store) Tokens() []Token {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Token, 0, len(s.d.Tokens))
	for _, t := range s.d.Tokens {
		out = append(out, *t)
	}
	return out
}

// Authenticate finds the token matching plain and marks it used.
func (s *Store) Authenticate(plain string) (Token, bool) {
	h := hashToken(plain)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.d.Tokens {
		if t.Hash != "" && t.Hash == h {
			t.LastUsed = time.Now()
			s.save()
			return *t, true
		}
	}
	return Token{}, false
}

func (s *Store) DeleteToken(id string) error {
	return s.update(func(d *data) error {
		d.Tokens = slices.DeleteFunc(d.Tokens, func(t *Token) bool { return t.ID == id })
		return nil
	})
}

// ---- ssh keys ----

func (s *Store) AddKey(name, line string, tunnels []string) error {
	pk, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(line)))
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}
	if name == "" {
		name = comment
	}
	fp := ssh.FingerprintSHA256(pk)
	normalized := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
	return s.update(func(d *data) error {
		for _, k := range d.Keys {
			if k.Fingerprint == fp {
				return fmt.Errorf("key %s already added as %q", fp, k.Name)
			}
		}
		d.Keys = append(d.Keys, &SSHKey{ID: randHex(6), Name: name, Key: normalized, Fingerprint: fp, Tunnels: tunnels, Created: time.Now()})
		return nil
	})
}

func (s *Store) Keys() []SSHKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]SSHKey, 0, len(s.d.Keys))
	for _, k := range s.d.Keys {
		out = append(out, *k)
	}
	return out
}

// KeysFor returns authorized_keys lines allowed for the given tunnel.
func (s *Store) KeysFor(tunnel string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []string{}
	for _, k := range s.d.Keys {
		if len(k.Tunnels) == 0 || slices.Contains(k.Tunnels, tunnel) {
			out = append(out, k.Key)
		}
	}
	return out
}

func (s *Store) DeleteKey(id string) error {
	return s.update(func(d *data) error {
		d.Keys = slices.DeleteFunc(d.Keys, func(k *SSHKey) bool { return k.ID == id })
		return nil
	})
}

// ---- domains ----

func (s *Store) AddDomain(host, tunnel string) error {
	return s.update(func(d *data) error {
		for _, x := range d.Domains {
			if x.Host == host {
				return fmt.Errorf("domain %s already exists", host)
			}
		}
		d.Domains = append(d.Domains, &Domain{Host: host, Tunnel: tunnel, Created: time.Now()})
		return nil
	})
}

func (s *Store) Domains() []Domain {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Domain, 0, len(s.d.Domains))
	for _, x := range s.d.Domains {
		out = append(out, *x)
	}
	return out
}

func (s *Store) Domain(host string) (Domain, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.d.Domains {
		if x.Host == host {
			return *x, true
		}
	}
	return Domain{}, false
}

func (s *Store) SetDomainStatus(host string, verr error) error {
	return s.update(func(d *data) error {
		for _, x := range d.Domains {
			if x.Host == host {
				x.Verified = verr == nil
				x.Error = ""
				if verr != nil {
					x.Error = verr.Error()
				}
				x.CheckedAt = time.Now()
			}
		}
		return nil
	})
}

func (s *Store) DeleteDomain(host string) error {
	return s.update(func(d *data) error {
		d.Domains = slices.DeleteFunc(d.Domains, func(x *Domain) bool { return x.Host == host })
		return nil
	})
}

// ---- reservations ----

func (s *Store) Reservation(name string) (Reservation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.d.Reservations[name]
	if !ok {
		return Reservation{}, false
	}
	return *r, true
}

func (s *Store) Reservations() []Reservation {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Reservation, 0, len(s.d.Reservations))
	for _, r := range s.d.Reservations {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Store) PortInUse(port int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.d.Reservations {
		if r.Port == port {
			return true
		}
	}
	return false
}

func (s *Store) PutReservation(r Reservation) error {
	return s.update(func(d *data) error {
		d.Reservations[r.Name] = &r
		return nil
	})
}

func (s *Store) DeleteReservation(name string) error {
	return s.update(func(d *data) error {
		delete(d.Reservations, name)
		return nil
	})
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

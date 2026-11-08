package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/ncruces/go-sqlite3/driver"
)

const tokenPrefix = "ac_"

// TokenInfo — налаштування токена (без секрету). Сам токен у БД не зберігається — лише SHA-256.
type TokenInfo struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Created    time.Time `json:"created"`
	Expires    time.Time `json:"expires,omitzero"`
	RPM        int       `json:"rpm"`
	Streams    int       `json:"streams"`
	Regions    []string  `json:"regions"` // порожньо — усі
	Nets       []string  `json:"nets"`    // порожньо — будь-які адреси
	AllowQuery bool      `json:"allowQuery"`

	LastSeen time.Time `json:"lastSeen,omitzero"`
	LastIP   string    `json:"lastIp,omitempty"`
	Requests int64     `json:"requests"`
	Denied   int64     `json:"denied"`
}

// token — токен у пам'яті служби: налаштування, розібрані мережі, ліміт запитів, лічильники.
type token struct {
	TokenInfo
	hash     string
	prefixes []netip.Prefix
	bucket   *bucket

	requests, denied atomic.Int64
	lastSeen         atomic.Int64
	lastIP           atomic.Value // string
	dirty            atomic.Bool
}

// Tokens — сховище (SQLite) і швидкий пошук за хешем.
type Tokens struct {
	db     *sql.DB
	mu     sync.RWMutex
	byHash map[string]*token
	byID   map[string]*token
	now    func() time.Time
}

const tokenSchema = `
CREATE TABLE IF NOT EXISTS tokens (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  hash        TEXT NOT NULL UNIQUE,
  created_ms  INTEGER NOT NULL,
  expires_ms  INTEGER NOT NULL DEFAULT 0,
  rpm         INTEGER NOT NULL,
  streams     INTEGER NOT NULL,
  regions     TEXT NOT NULL DEFAULT '[]',
  nets        TEXT NOT NULL DEFAULT '[]',
  allow_query INTEGER NOT NULL DEFAULT 0,
  last_seen_ms INTEGER NOT NULL DEFAULT 0,
  last_ip     TEXT NOT NULL DEFAULT '',
  requests    INTEGER NOT NULL DEFAULT 0,
  denied      INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;
`

func OpenTokens(path string) (*Tokens, error) {
	dsn := "file:" + path + "?_txlock=immediate&_pragma=journal_mode(wal)&_pragma=synchronous(normal)" +
		"&_pragma=busy_timeout(5000)&_pragma=hard_heap_limit(33554432)&_pragma=trusted_schema(0)"
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(tokenSchema); err != nil {
		db.Close()
		return nil, err
	}
	t := &Tokens{db: db, now: time.Now}
	if err := t.load(); err != nil {
		db.Close()
		return nil, err
	}
	return t, nil
}

func (t *Tokens) Close() {
	t.FlushStats()
	t.db.Close()
}

func (t *Tokens) load() error {
	rows, err := t.db.Query(`SELECT id,name,hash,created_ms,expires_ms,rpm,streams,regions,nets,allow_query,
		last_seen_ms,last_ip,requests,denied FROM tokens`)
	if err != nil {
		return err
	}
	defer rows.Close()
	byHash, byID := map[string]*token{}, map[string]*token{}
	for rows.Next() {
		var tk token
		var created, expires, seen int64
		var regions, nets string
		var allowQ int
		if err := rows.Scan(&tk.ID, &tk.Name, &tk.hash, &created, &expires, &tk.RPM, &tk.Streams, &regions, &nets,
			&allowQ, &seen, &tk.LastIP, &tk.Requests, &tk.Denied); err != nil {
			return err
		}
		tk.Created = time.UnixMilli(created)
		if expires > 0 {
			tk.Expires = time.UnixMilli(expires)
		}
		_ = json.Unmarshal([]byte(regions), &tk.Regions)
		_ = json.Unmarshal([]byte(nets), &tk.Nets)
		tk.AllowQuery = allowQ != 0
		if err := tk.prepare(); err != nil {
			return fmt.Errorf("token %s: %w", tk.ID, err)
		}
		tk.requests.Store(tk.Requests)
		tk.denied.Store(tk.Denied)
		tk.lastSeen.Store(seen)
		tk.lastIP.Store(tk.LastIP)
		p := &tk
		byHash[tk.hash], byID[tk.ID] = p, p
	}
	if err := rows.Err(); err != nil {
		return err
	}
	t.mu.Lock()
	t.byHash, t.byID = byHash, byID
	t.mu.Unlock()
	return nil
}

func (tk *token) prepare() error {
	tk.prefixes = tk.prefixes[:0]
	for _, n := range tk.Nets {
		p, err := parseNet(n)
		if err != nil {
			return err
		}
		tk.prefixes = append(tk.prefixes, p)
	}
	tk.bucket = newBucket(tk.RPM)
	if tk.Regions == nil {
		tk.Regions = []string{}
	}
	if tk.Nets == nil {
		tk.Nets = []string{}
	}
	return nil
}

func parseNet(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("некоректна адреса %q", s)
		}
		return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("некоректна мережа %q", s)
	}
	return p.Masked(), nil
}

func hashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

func newSecret() (raw, hash string) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	raw = tokenPrefix + base64.RawURLEncoding.EncodeToString(b[:])
	return raw, hashToken(raw)
}

func newID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// looksLikeToken — дешева перевірка формату до обчислення хешу (відсікає сміття).
func looksLikeToken(s string) bool {
	if len(s) != len(tokenPrefix)+43 || !strings.HasPrefix(s, tokenPrefix) {
		return false
	}
	for i := len(tokenPrefix); i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

var (
	errAuth = errors.New("unauthorized")
)

// deniedErr — відомий токен, але відмова (термін, адреса, ?token=). Назовні — та сама 401;
// ID потрібен лише для статистики токена в адмінці.
type deniedErr struct{ id string }

func (deniedErr) Error() string { return errAuth.Error() }
func (deniedErr) Unwrap() error { return errAuth }

// Check — токен за сирим значенням, адресою клієнта і способом передачі. Будь-яка причина
// відмови (невідомий, прострочений, чужа адреса, токен у запиті без дозволу) — одна errAuth.
func (t *Tokens) Check(raw string, ip netip.Addr, viaQuery bool) (*token, error) {
	if !looksLikeToken(raw) {
		return nil, errAuth
	}
	h := hashToken(raw)
	t.mu.RLock()
	tk := t.byHash[h]
	t.mu.RUnlock()
	if tk == nil {
		return nil, errAuth
	}
	return t.admit(tk, ip, viaQuery)
}

// admit — перевірка обмежень уже знайденого токена (для запиту з токеном і для сесії).
func (t *Tokens) admit(tk *token, ip netip.Addr, viaQuery bool) (*token, error) {
	if !t.Current(tk) { // токен змінено або відкликано після створення сесії
		return nil, errAuth
	}
	deny := func() (*token, error) {
		tk.denied.Add(1)
		tk.dirty.Store(true)
		return nil, deniedErr{tk.ID}
	}
	if !tk.Expires.IsZero() && !t.now().Before(tk.Expires) {
		return deny()
	}
	if viaQuery && !tk.AllowQuery {
		return deny()
	}
	if len(tk.prefixes) > 0 {
		ok := false
		for _, p := range tk.prefixes {
			if ip.IsValid() && p.Contains(ip.Unmap()) {
				ok = true
				break
			}
		}
		if !ok {
			return deny()
		}
	}
	now := t.now()
	tk.requests.Add(1)
	tk.lastSeen.Store(now.UnixMilli())
	tk.lastIP.Store(ip.String())
	tk.dirty.Store(true)
	return tk, nil
}

// Allowed — чи може токен бачити регіон: сам регіон або будь-який його предок у списку.
func (tk *token) Allowed(tree *Tree, id string) bool {
	if isTestRegion(id) { // тестова область — лише явно, «усі регіони» її не включають
		for _, r := range tk.Regions {
			if isTestRegion(r) && tree.Within(id, r) {
				return true
			}
		}
		return false
	}
	if len(tk.Regions) == 0 {
		return true
	}
	for _, r := range tk.Regions {
		if tree.Within(id, r) {
			return true
		}
	}
	return false
}

// Expired — для потоків: перевіряється періодично.
func (tk *token) Expired(now time.Time) bool { return !tk.Expires.IsZero() && !now.Before(tk.Expires) }

func (t *Tokens) byIDGet(id string) *token {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.byID[id]
}

// Current — чи токен досі чинний у тому самому вигляді (не відкликаний і не змінений).
func (t *Tokens) Current(tk *token) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.byID[tk.ID] == tk
}

func (tk *token) info() TokenInfo {
	i := tk.TokenInfo
	i.Requests, i.Denied = tk.requests.Load(), tk.denied.Load()
	if v := tk.lastSeen.Load(); v > 0 {
		i.LastSeen = time.UnixMilli(v)
	}
	i.LastIP, _ = tk.lastIP.Load().(string)
	i.Regions = append([]string{}, tk.Regions...)
	i.Nets = append([]string{}, tk.Nets...)
	return i
}

func (t *Tokens) List() []TokenInfo {
	t.mu.RLock()
	out := make([]TokenInfo, 0, len(t.byID))
	for _, tk := range t.byID {
		out = append(out, tk.info())
	}
	t.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out
}

// TokenSpec — що можна задати при створенні чи зміні (nil — не змінювати).
type TokenSpec struct {
	Name       *string    `json:"name,omitempty"`
	Expires    *time.Time `json:"expires,omitempty"` // нульовий час — без терміну
	RPM        *int       `json:"rpm,omitempty"`
	Streams    *int       `json:"streams,omitempty"`
	Regions    *[]string  `json:"regions,omitempty"`
	Nets       *[]string  `json:"nets,omitempty"`
	AllowQuery *bool      `json:"allowQuery,omitempty"`
}

const (
	maxRPM        = 6000
	maxStreams    = 100
	maxTokenNames = 64
)

func (sp TokenSpec) apply(tk *token, tree *Tree) error {
	if sp.Name != nil {
		n := strings.TrimSpace(*sp.Name)
		if n == "" || len([]rune(n)) > maxTokenNames || strings.ContainsAny(n, "\x00\r\n\t") {
			return errors.New("назва: 1–64 символи, без керівних")
		}
		tk.Name = n
	}
	if sp.Expires != nil {
		tk.Expires = *sp.Expires
	}
	if sp.RPM != nil {
		if *sp.RPM < 1 || *sp.RPM > maxRPM {
			return fmt.Errorf("rpm: 1–%d", maxRPM)
		}
		tk.RPM = *sp.RPM
	}
	if sp.Streams != nil {
		if *sp.Streams < 0 || *sp.Streams > maxStreams {
			return fmt.Errorf("streams: 0–%d", maxStreams)
		}
		tk.Streams = *sp.Streams
	}
	if sp.Regions != nil {
		seen := map[string]bool{}
		out := []string{}
		for _, r := range *sp.Regions {
			r = strings.TrimSpace(r)
			if r == "" || seen[r] {
				continue
			}
			if !validID(r) {
				return fmt.Errorf("регіон %q: лише цифри", r)
			}
			if tree.Len() > 0 {
				if _, ok := tree.Get(r); !ok {
					return fmt.Errorf("регіон %s не існує (див. /api/v1/regions)", r)
				}
			}
			seen[r] = true
			out = append(out, r)
		}
		if len(out) > 256 {
			return errors.New("regions: не більше 256")
		}
		tk.Regions = out
	}
	if sp.Nets != nil {
		out := []string{}
		for _, n := range *sp.Nets {
			if strings.TrimSpace(n) == "" {
				continue
			}
			p, err := parseNet(n)
			if err != nil {
				return err
			}
			out = append(out, p.String())
		}
		if len(out) > 64 {
			return errors.New("ip: не більше 64 мереж")
		}
		tk.Nets = out
	}
	if sp.AllowQuery != nil {
		tk.AllowQuery = *sp.AllowQuery
	}
	return tk.prepare()
}

func (t *Tokens) save(tk *token) error {
	regions, _ := json.Marshal(tk.Regions)
	nets, _ := json.Marshal(tk.Nets)
	var exp int64
	if !tk.Expires.IsZero() {
		exp = tk.Expires.UnixMilli()
	}
	_, err := t.db.Exec(`INSERT INTO tokens (id,name,hash,created_ms,expires_ms,rpm,streams,regions,nets,allow_query,
		last_seen_ms,last_ip,requests,denied) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name, hash=excluded.hash, expires_ms=excluded.expires_ms,
		rpm=excluded.rpm, streams=excluded.streams, regions=excluded.regions, nets=excluded.nets,
		allow_query=excluded.allow_query`,
		tk.ID, tk.Name, tk.hash, tk.Created.UnixMilli(), exp, tk.RPM, tk.Streams, string(regions), string(nets),
		boolInt(tk.AllowQuery), tk.lastSeen.Load(), lastIP(tk), tk.requests.Load(), tk.denied.Load())
	return err
}

func lastIP(tk *token) string { s, _ := tk.lastIP.Load().(string); return s }

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Add створює токен; повертає сирий токен (показується один раз).
func (t *Tokens) Add(sp TokenSpec, tree *Tree, defRPM, defStreams int) (TokenInfo, string, error) {
	if sp.Name == nil {
		return TokenInfo{}, "", errors.New("потрібна назва (--name)")
	}
	tk := &token{TokenInfo: TokenInfo{Created: t.now(), RPM: defRPM, Streams: defStreams}}
	if err := sp.apply(tk, tree); err != nil {
		return TokenInfo{}, "", err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for {
		tk.ID = newID()
		if t.byID[tk.ID] == nil {
			break
		}
	}
	raw, h := newSecret()
	tk.hash = h
	tk.lastIP.Store("")
	if err := t.save(tk); err != nil {
		return TokenInfo{}, "", err
	}
	t.byHash[h], t.byID[tk.ID] = tk, tk
	return tk.info(), raw, nil
}

// Edit змінює налаштування. Старий об'єкт замінюється новим: відкриті потоки цього токена
// завершуються (клієнт перепідключиться вже з новими правилами).
func (t *Tokens) Edit(id string, sp TokenSpec, tree *Tree, rotate bool) (TokenInfo, string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	old := t.byID[id]
	if old == nil {
		return TokenInfo{}, "", fmt.Errorf("токена %s немає", id)
	}
	tk := &token{TokenInfo: old.TokenInfo, hash: old.hash}
	tk.Regions = append([]string{}, old.Regions...)
	tk.Nets = append([]string{}, old.Nets...)
	tk.requests.Store(old.requests.Load())
	tk.denied.Store(old.denied.Load())
	tk.lastSeen.Store(old.lastSeen.Load())
	tk.lastIP.Store(lastIP(old))
	if err := sp.apply(tk, tree); err != nil {
		return TokenInfo{}, "", err
	}
	raw := ""
	if rotate {
		raw, tk.hash = newSecret()
	}
	if err := t.save(tk); err != nil {
		return TokenInfo{}, "", err
	}
	delete(t.byHash, old.hash)
	t.byHash[tk.hash], t.byID[id] = tk, tk
	return tk.info(), raw, nil
}

func (t *Tokens) Revoke(id string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	tk := t.byID[id]
	if tk == nil {
		return fmt.Errorf("токена %s немає", id)
	}
	if _, err := t.db.Exec(`DELETE FROM tokens WHERE id=?`, id); err != nil {
		return err
	}
	delete(t.byHash, tk.hash)
	delete(t.byID, id)
	return nil
}

func (t *Tokens) Get(id string) (TokenInfo, bool) {
	tk := t.byIDGet(id)
	if tk == nil {
		return TokenInfo{}, false
	}
	return tk.info(), true
}

// FlushStats пише лічильники в БД (раз на хвилину й при зупинці).
func (t *Tokens) FlushStats() {
	t.mu.RLock()
	var list []*token
	for _, tk := range t.byID {
		if tk.dirty.Swap(false) {
			list = append(list, tk)
		}
	}
	t.mu.RUnlock()
	for _, tk := range list {
		_, err := t.db.Exec(`UPDATE tokens SET last_seen_ms=?, last_ip=?, requests=?, denied=? WHERE id=?`,
			tk.lastSeen.Load(), lastIP(tk), tk.requests.Load(), tk.denied.Load(), tk.ID)
		if err != nil {
			tk.dirty.Store(true)
			logf("token stats: %v", err)
			return
		}
	}
}

// ---------- ліміти ----------

// bucket — «відро з токенами»: rpm запитів на хвилину, сплеск до burst.
type bucket struct {
	mu     sync.Mutex
	rate   float64 // за секунду
	burst  float64
	tokens float64
	last   time.Time
}

func newBucket(rpm int) *bucket {
	burst := float64(rpm) / 6
	if burst < 3 {
		burst = 3
	}
	if burst > float64(rpm) {
		burst = float64(rpm)
	}
	return &bucket{rate: float64(rpm) / 60, burst: burst, tokens: burst}
}

// take — дозволити запит; інакше — через скільки буде можна.
func (b *bucket) take(now time.Time) (bool, time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.last.IsZero() {
		b.tokens += now.Sub(b.last).Seconds() * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / b.rate * float64(time.Second))
	return false, wait
}

// ipGuard — ліміти до перевірки токена: запитів з однієї адреси та блокування після
// серії невдалих спроб автентифікації. Пам'ять обмежена (maxEntries адрес).
type ipGuard struct {
	mu         sync.Mutex
	m          map[netip.Addr]*ipEntry
	rpm        int
	failLimit  int
	failWindow time.Duration
	banFor     time.Duration
	maxEntries int
	bans       atomic.Int64
}

type ipEntry struct {
	b          *bucket
	fails      int
	failSince  time.Time
	banUntil   time.Time
	lastActive time.Time
}

func newIPGuard(rpm, failLimit int, failWindow, banFor time.Duration) *ipGuard {
	return &ipGuard{m: map[netip.Addr]*ipEntry{}, rpm: rpm, failLimit: failLimit, failWindow: failWindow,
		banFor: banFor, maxEntries: 200000}
}

func ipKey(a netip.Addr) netip.Addr {
	a = a.Unmap()
	if a.Is6() { // IPv6 — за /64: одна «людина» зазвичай має всю мережу
		p, _ := a.Prefix(64)
		return p.Addr()
	}
	return a
}

// allow — чи пускати запит з цієї адреси; retry — через скільки повторити.
func (g *ipGuard) allow(a netip.Addr, now time.Time) (bool, time.Duration) {
	k := ipKey(a)
	g.mu.Lock()
	defer g.mu.Unlock()
	e := g.m[k]
	if e == nil {
		if len(g.m) >= g.maxEntries {
			g.gcLocked(now)
			if len(g.m) >= g.maxEntries {
				return false, time.Minute
			}
		}
		e = &ipEntry{b: newBucket(g.rpm)}
		g.m[k] = e
	}
	e.lastActive = now
	if now.Before(e.banUntil) {
		return false, e.banUntil.Sub(now)
	}
	return e.b.take(now)
}

// fail — невдала автентифікація; true — адресу щойно заблоковано.
func (g *ipGuard) fail(a netip.Addr, now time.Time) bool {
	k := ipKey(a)
	g.mu.Lock()
	defer g.mu.Unlock()
	e := g.m[k]
	if e == nil {
		return false
	}
	if now.Sub(e.failSince) > g.failWindow {
		e.fails, e.failSince = 0, now
	}
	e.fails++
	if e.fails >= g.failLimit {
		e.banUntil, e.fails = now.Add(g.banFor), 0
		g.bans.Add(1)
		return true
	}
	return false
}

func (g *ipGuard) gcLocked(now time.Time) {
	for k, e := range g.m {
		if now.Sub(e.lastActive) > 10*time.Minute && now.After(e.banUntil) {
			delete(g.m, k)
		}
	}
}

func (g *ipGuard) gc(now time.Time) {
	g.mu.Lock()
	g.gcLocked(now)
	g.mu.Unlock()
}

func (g *ipGuard) size() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.m)
}

// Ban — заблокована адреса (для адмінки).
type Ban struct {
	IP    string    `json:"ip"`
	Until time.Time `json:"until"`
}

func (g *ipGuard) Bans(now time.Time) []Ban {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := []Ban{}
	for k, e := range g.m {
		if now.Before(e.banUntil) {
			ip := k.String()
			if k.Is6() {
				ip += "/64"
			}
			out = append(out, Ban{IP: ip, Until: e.banUntil})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Until.Before(out[j].Until) })
	return out
}

// Unban — зняти блокування (адреса як у Bans, з /64 для IPv6).
func (g *ipGuard) Unban(ip string) bool {
	a, err := netip.ParseAddr(strings.TrimSuffix(ip, "/64"))
	if err != nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	e := g.m[ipKey(a)]
	if e == nil || e.banUntil.IsZero() {
		return false
	}
	e.banUntil, e.fails = time.Time{}, 0
	return true
}

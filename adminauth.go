package main

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Вхід в адмінку: пароль (PBKDF2-SHA256, 600 000 ітерацій) + одноразовий код 2FA (TOTP,
// RFC 6238: SHA-1, 6 цифр, 30 с). Код приймається лише один раз — повтор перехопленого коду
// не спрацює. Адмін один; задається командою `sudo alertcast admin setup`.

const (
	pbkdfIter     = 600_000
	totpPeriod    = 30
	totpSkew      = 1 // ±1 крок (годинник телефону може трохи відставати)
	adminCookie   = "__Host-ac_admin"
	adminIdle     = 30 * time.Minute
	adminAbsolute = 12 * time.Hour
	adminMaxSess  = 5

	loginIPFails     = 5 // на адресу за loginWindow → блок loginIPBan
	loginWindow      = 15 * time.Minute
	loginIPBan       = 15 * time.Minute
	loginGlobalFails = 20 // усього за loginWindow → вхід закрито для всіх на loginGlobalLock
	loginGlobalLock  = 5 * time.Minute
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func hashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	k, err := pbkdf2.Key(sha256.New, pw, salt, pbkdfIter, 32)
	if err != nil {
		return "", err
	}
	e := base64.RawStdEncoding
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdfIter, e.EncodeToString(salt), e.EncodeToString(k)), nil
}

// dummyHash — щоб перевірка без налаштованого пароля тривала стільки ж.
var dummyHash = "pbkdf2-sha256$600000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func checkPassword(stored, pw string) bool {
	p := strings.Split(stored, "$")
	if len(p) != 4 || p[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(p[1])
	if err != nil || iter < 100_000 || iter > 10_000_000 {
		return false
	}
	e := base64.RawStdEncoding
	salt, err1 := e.DecodeString(p[2])
	want, err2 := e.DecodeString(p[3])
	if err1 != nil || err2 != nil || len(want) != 32 {
		return false
	}
	k, err := pbkdf2.Key(sha256.New, pw, salt, iter, 32)
	return err == nil && subtle.ConstantTimeCompare(k, want) == 1
}

func newTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b32.EncodeToString(b), nil
}

func totpAt(secret string, step int64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	s := m.Sum(nil)
	o := s[len(s)-1] & 0x0f
	v := binary.BigEndian.Uint32(s[o:o+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1_000_000), nil
}

// totpMatch — крок, якому відповідає код (у межах ±totpSkew), або -1.
func totpMatch(secret, code string, now time.Time) int64 {
	if len(code) != 6 {
		return -1
	}
	cur := now.Unix() / totpPeriod
	found := int64(-1)
	for d := -totpSkew; d <= totpSkew; d++ { // без раннього виходу — рівний час
		c, err := totpAt(secret, cur+int64(d))
		if err == nil && subtle.ConstantTimeCompare([]byte(c), []byte(code)) == 1 {
			found = cur + int64(d)
		}
	}
	return found
}

func otpauthURI(secret, account string) string {
	v := url.Values{"secret": {secret}, "issuer": {"alertcast"}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + url.PathEscape("alertcast:"+account) + "?" + v.Encode()
}

// ---------- сховище й сесії ----------

type adminSess struct {
	csrf    string
	ip      string
	created time.Time
	seen    time.Time
}

type AdminAuth struct {
	mu       sync.Mutex
	db       *sql.DB
	pw, totp string
	lastStep int64
	sess     map[string]*adminSess // hash(id) → сесія
	fails    map[netip.Addr][]time.Time
	banned   map[netip.Addr]time.Time
	nextTry  map[netip.Addr]time.Time // наростаюча пауза після кожної невдачі: 1, 2, 4, 8, 16 с
	global   []time.Time
	lockTill time.Time
	verify   sync.Mutex // одна перевірка пароля за раз: PBKDF2 не стане засобом DoS
	now      func() time.Time
}

func NewAdminAuth(db *sql.DB) (*AdminAuth, error) {
	a := &AdminAuth{db: db, sess: map[string]*adminSess{}, fails: map[netip.Addr][]time.Time{},
		banned: map[netip.Addr]time.Time{}, nextTry: map[netip.Addr]time.Time{}, now: time.Now}
	if db == nil {
		return a, nil
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS admin_auth (id INTEGER PRIMARY KEY CHECK (id = 1),
		pw TEXT NOT NULL, totp TEXT NOT NULL, last_step INTEGER NOT NULL DEFAULT 0)`); err != nil {
		return nil, err
	}
	err := db.QueryRow(`SELECT pw, totp, last_step FROM admin_auth WHERE id = 1`).Scan(&a.pw, &a.totp, &a.lastStep)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	return a, nil
}

func (a *AdminAuth) Configured() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.pw != "" && a.totp != ""
}

// Set — новий пароль і секрет 2FA; усі сесії адміна завершуються.
func (a *AdminAuth) Set(pwHash, secret string) error {
	if !strings.HasPrefix(pwHash, "pbkdf2-sha256$") {
		return errors.New("невірний формат хешу пароля")
	}
	if k, err := b32.DecodeString(secret); err != nil || len(k) < 16 {
		return errors.New("невірний секрет 2FA")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.db != nil {
		if _, err := a.db.Exec(`INSERT INTO admin_auth(id, pw, totp, last_step) VALUES (1, ?, ?, 0)
			ON CONFLICT(id) DO UPDATE SET pw = excluded.pw, totp = excluded.totp, last_step = 0`, pwHash, secret); err != nil {
			return err
		}
	}
	a.pw, a.totp, a.lastStep = pwHash, secret, 0
	a.sess = map[string]*adminSess{}
	return nil
}

func (a *AdminAuth) LogoutAll() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := len(a.sess)
	a.sess = map[string]*adminSess{}
	return n
}

var (
	errLoginBlocked = errors.New("забагато невдалих спроб — спробуйте пізніше")
	errLoginBad     = errors.New("невірний пароль або код")
	errNotSetup     = errors.New("вхід не налаштовано: sudo alertcast admin setup")
)

func pruneTimes(ts []time.Time, cut time.Time) []time.Time {
	i := 0
	for i < len(ts) && !ts[i].After(cut) {
		i++
	}
	return ts[i:]
}

// blocked — чи закрито вхід для адреси; retry — через скільки можна.
func (a *AdminAuth) blocked(ip netip.Addr) (bool, time.Duration) {
	now := a.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	if t, ok := a.banned[ip]; ok {
		if now.Before(t) {
			return true, t.Sub(now)
		}
		delete(a.banned, ip)
	}
	if now.Before(a.lockTill) {
		return true, a.lockTill.Sub(now)
	}
	if t, ok := a.nextTry[ip]; ok {
		if now.Before(t) {
			return true, t.Sub(now)
		}
		delete(a.nextTry, ip)
	}
	return false, 0
}

// begin — перевірити блокування й одразу зайняти «слот» спроби (одна перевірка й запис під
// одним замком: паралельні запити з однієї адреси не проскочать між ними).
func (a *AdminAuth) begin(ip netip.Addr) bool {
	now := a.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	if t, ok := a.banned[ip]; ok && now.Before(t) {
		return false
	}
	if now.Before(a.lockTill) {
		return false
	}
	if t, ok := a.nextTry[ip]; ok && now.Before(t) {
		return false
	}
	a.nextTry[ip] = now.Add(time.Second)
	return true
}

// fail — невдала спроба; повертає текст для журналу, якщо щось заблоковано.
func (a *AdminAuth) fail(ip netip.Addr) string {
	now := a.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	cut := now.Add(-loginWindow)
	a.fails[ip] = append(pruneTimes(a.fails[ip], cut), now)
	a.global = append(pruneTimes(a.global, cut), now)
	if len(a.fails) > 10000 { // захист пам'яті
		for k, v := range a.fails {
			if len(pruneTimes(v, cut)) == 0 {
				delete(a.fails, k)
			}
		}
	}
	msg := ""
	a.nextTry[ip] = now.Add(time.Second << (len(a.fails[ip]) - 1))
	if len(a.nextTry) > 10000 {
		a.nextTry = map[netip.Addr]time.Time{ip: a.nextTry[ip]}
	}
	if len(a.fails[ip]) >= loginIPFails {
		a.banned[ip] = now.Add(loginIPBan)
		delete(a.fails, ip)
		msg = fmt.Sprintf("Вхід в адмінку для адреси заблоковано на %s після %d невдалих спроб", humanDur(loginIPBan), loginIPFails)
	}
	if len(a.global) >= loginGlobalFails {
		a.lockTill = now.Add(loginGlobalLock)
		a.global = nil
		msg = fmt.Sprintf("Вхід в адмінку закрито для всіх на %s: %d невдалих спроб за %s", humanDur(loginGlobalLock), loginGlobalFails, humanDur(loginWindow))
	}
	return msg
}

// Login — перевірка пароля й коду. Повертає id сесії (у cookie) і CSRF-токен.
// Помилка не уточнює, що саме невірне.
func (a *AdminAuth) Login(ip netip.Addr, pw, code string) (id, csrf, banMsg string, err error) {
	if !a.begin(ip) {
		return "", "", "", errLoginBlocked
	}
	if len(pw) > 1024 {
		pw = pw[:1024]
	}
	a.mu.Lock()
	stored, secret := a.pw, a.totp
	a.mu.Unlock()
	a.verify.Lock()
	okPW := checkPassword(orDefault(stored, dummyHash), pw)
	a.verify.Unlock()
	if stored == "" || secret == "" {
		return "", "", "", errNotSetup
	}
	step := totpMatch(secret, strings.TrimSpace(code), a.now())
	a.mu.Lock()
	replay := step >= 0 && step <= a.lastStep
	a.mu.Unlock()
	if !okPW || step < 0 || replay {
		return "", "", a.fail(ip), errLoginBad
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if step <= a.lastStep { // паралельний вхід тим самим кодом
		return "", "", "", errLoginBad
	}
	a.lastStep = step
	if a.db != nil {
		if _, err := a.db.Exec(`UPDATE admin_auth SET last_step = ? WHERE id = 1`, step); err != nil {
			return "", "", "", err
		}
	}
	delete(a.fails, ip)
	delete(a.nextTry, ip)
	now := a.now()
	for len(a.sess) >= adminMaxSess {
		var oldK string
		var oldT time.Time
		for k, s := range a.sess {
			if oldK == "" || s.created.Before(oldT) {
				oldK, oldT = k, s.created
			}
		}
		delete(a.sess, oldK)
	}
	id, csrf = randID(), randID()
	if id == "" || csrf == "" {
		return "", "", "", errors.New("rand")
	}
	a.sess[hashToken(id)] = &adminSess{csrf: csrf, ip: ip.String(), created: now, seen: now}
	return id, csrf, "", nil
}

func randID() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// Session — дійсна сесія (і продовжити її простій); nil — немає.
func (a *AdminAuth) Session(id string, touch bool) *adminSess {
	if len(id) != sessionIDLength {
		return nil
	}
	k := hashToken(id)
	now := a.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.sess[k]
	if s == nil {
		return nil
	}
	if now.Sub(s.seen) >= adminIdle || now.Sub(s.created) >= adminAbsolute {
		delete(a.sess, k)
		return nil
	}
	if touch {
		s.seen = now
	}
	c := *s
	return &c
}

func (a *AdminAuth) Logout(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.sess, hashToken(id))
}

func (a *AdminAuth) GC() {
	now := a.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, s := range a.sess {
		if now.Sub(s.seen) >= adminIdle || now.Sub(s.created) >= adminAbsolute {
			delete(a.sess, k)
		}
	}
	for ip, t := range a.banned {
		if !now.Before(t) {
			delete(a.banned, ip)
		}
	}
	for ip, t := range a.nextTry {
		if !now.Before(t) {
			delete(a.nextTry, ip)
		}
	}
	cut := now.Add(-loginWindow)
	for ip, v := range a.fails {
		if v = pruneTimes(v, cut); len(v) == 0 {
			delete(a.fails, ip)
		} else {
			a.fails[ip] = v
		}
	}
}

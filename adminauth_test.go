package main

import (
	"encoding/base32"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestTOTPVectors(t *testing.T) {
	// RFC 6238, додаток B (SHA-1), останні 6 цифр
	sec := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	for _, v := range []struct {
		t    int64
		want string
	}{{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"}, {2000000000, "279037"}, {20000000000, "353130"}} {
		got, err := totpAt(sec, v.t/30)
		if err != nil || got != v.want {
			t.Fatalf("T=%d: %s %v, want %s", v.t, got, err, v.want)
		}
	}
	now := time.Unix(1111111111, 0)
	if totpMatch(sec, "050471", now) != 1111111111/30 || totpMatch(sec, "081804", now) != 1111111109/30 {
		t.Fatal("current/previous step")
	}
	if totpMatch(sec, "005924", now) != -1 || totpMatch(sec, "", now) != -1 || totpMatch(sec, "05047", now) != -1 {
		t.Fatal("far/empty/short code accepted")
	}
	if u := otpauthURI(sec, "admin"); !strings.HasPrefix(u, "otpauth://totp/alertcast:admin?") || !strings.Contains(u, "secret="+sec) {
		t.Fatal(u)
	}
}

func TestPasswordHash(t *testing.T) {
	h, err := hashPassword("правильний кінь батарея")
	if err != nil || !strings.HasPrefix(h, "pbkdf2-sha256$600000$") {
		t.Fatal(h, err)
	}
	if !checkPassword(h, "правильний кінь батарея") || checkPassword(h, "правильний кінь батареЯ") || checkPassword(h, "") {
		t.Fatal("check")
	}
	h2, _ := hashPassword("правильний кінь батарея")
	if h2 == h {
		t.Fatal("no salt")
	}
	for _, bad := range []string{"", "x", "pbkdf2-sha256$1$AA$AA", "pbkdf2-sha256$600000$!!$AA", dummyHash, strings.Replace(h, "600000", "99999", 1)} {
		if checkPassword(bad, "x") {
			t.Fatalf("accepted %q", bad)
		}
	}
}

type authFixture struct {
	a      *AdminAuth
	clk    *fakeClock
	secret string
}

func newAuthFixture(t *testing.T) *authFixture {
	ta := newTestApp(t)
	au, err := NewAdminAuth(ta.tokens.db)
	if err != nil {
		t.Fatal(err)
	}
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	au.now = clk.now
	sec, _ := newTOTPSecret()
	h, _ := hashPassword("pass-pass-pass")
	if err := au.Set(h, sec); err != nil {
		t.Fatal(err)
	}
	return &authFixture{au, clk, sec}
}

func (f *authFixture) code(d int) string {
	c, _ := totpAt(f.secret, f.clk.t.Unix()/30+int64(d))
	return c
}

func TestAdminLogin(t *testing.T) {
	f := newAuthFixture(t)
	ip := netip.MustParseAddr("10.77.0.3")
	id, csrf, _, err := f.a.Login(ip, "pass-pass-pass", f.code(0))
	if err != nil || len(id) != 43 || len(csrf) != 43 {
		t.Fatal(id, csrf, err)
	}
	if s := f.a.Session(id, true); s == nil || s.csrf != csrf {
		t.Fatal("session")
	}
	// той самий код удруге (перехоплений) — ні, навіть з правильним паролем
	f.clk.t = f.clk.t.Add(2 * time.Second)
	if _, _, _, err := f.a.Login(netip.MustParseAddr("10.77.0.4"), "pass-pass-pass", f.code(0)); err != errLoginBad {
		t.Fatalf("replay: %v", err)
	}
	if n := len(f.a.fails[netip.MustParseAddr("10.77.0.4")]); n != 1 {
		t.Fatalf("replay must count as a failure: %d", n) // повтор коду — підозріло
	}
	// попередній крок теж уже «використаний»
	f.clk.t = f.clk.t.Add(30 * time.Second)
	if _, _, _, err := f.a.Login(netip.MustParseAddr("10.77.0.5"), "pass-pass-pass", f.code(-1)); err != errLoginBad {
		t.Fatalf("older step: %v", err)
	}
	if _, _, _, err := f.a.Login(netip.MustParseAddr("10.77.0.6"), "pass-pass-pass", f.code(0)); err != nil {
		t.Fatalf("next step: %v", err)
	}
	// повтор після перезапуску (з БД) теж не проходить
	au2, _ := NewAdminAuth(f.a.db)
	au2.now = f.clk.now
	if _, _, _, err := au2.Login(netip.MustParseAddr("10.77.0.7"), "pass-pass-pass", f.code(0)); err != errLoginBad {
		t.Fatalf("replay after restart: %v", err)
	}
	// простій 30 хв і абсолютні 12 год
	f.clk.t = f.clk.t.Add(29 * time.Minute)
	if f.a.Session(id, true) == nil {
		t.Fatal("expired too early")
	}
	f.clk.t = f.clk.t.Add(29 * time.Minute)
	if f.a.Session(id, false) == nil {
		t.Fatal("expired too early 2")
	}
	f.clk.t = f.clk.t.Add(2 * time.Minute) // не торкались 31 хв
	if f.a.Session(id, true) != nil {
		t.Fatal("idle session alive")
	}
	f.clk.t = f.clk.t.Add(time.Minute)
	id2, _, _, err := f.a.Login(ip, "pass-pass-pass", f.code(0))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 24*3; i++ { // активна, але 12 год — межа
		f.clk.t = f.clk.t.Add(10 * time.Minute)
		f.a.Session(id2, true)
	}
	if f.a.Session(id2, true) != nil {
		t.Fatal("absolute timeout")
	}
	// новий пароль — старі сесії недійсні
	f.clk.t = f.clk.t.Add(time.Minute)
	id3, _, _, _ := f.a.Login(ip, "pass-pass-pass", f.code(0))
	h, _ := hashPassword("new-new-new-new")
	f.a.Set(h, f.secret)
	if f.a.Session(id3, true) != nil {
		t.Fatal("session survived Set")
	}
	if f.a.Session("short", true) != nil {
		t.Fatal("bad id")
	}
}

func TestAdminLoginThrottle(t *testing.T) {
	f := newAuthFixture(t)
	ip := netip.MustParseAddr("10.77.0.9")
	for i := 1; i <= loginIPFails; i++ {
		if b, _ := f.a.blocked(ip); b && i > 1 {
			// пауза після невдачі: 1, 2, 4, 8 с
			f.clk.t = f.clk.t.Add(time.Second << (i - 2))
		}
		_, _, msg, err := f.a.Login(ip, "wrong-wrong", f.code(0))
		if err != errLoginBad {
			t.Fatalf("try %d: %v", i, err)
		}
		if (msg != "") != (i == loginIPFails) {
			t.Fatalf("try %d ban msg %q", i, msg)
		}
		if i < loginIPFails {
			if _, retry := f.a.blocked(ip); retry != time.Second<<(i-1) {
				t.Fatalf("try %d: delay %s", i, retry)
			}
		}
	}
	// заблоковано: навіть правильний пароль не перевіряється
	if _, _, _, err := f.a.Login(ip, "pass-pass-pass", f.code(0)); err != errLoginBlocked {
		t.Fatalf("banned: %v", err)
	}
	f.clk.t = f.clk.t.Add(loginIPBan)
	if _, _, _, err := f.a.Login(ip, "pass-pass-pass", f.code(0)); err != nil {
		t.Fatalf("after ban: %v", err)
	}
	// багато адрес — вхід закривається для всіх
	f.clk.t = f.clk.t.Add(time.Minute)
	var msg string
	for i := 0; i < loginGlobalFails; i++ {
		_, _, msg, _ = f.a.Login(netip.AddrFrom4([4]byte{10, 1, byte(i / 250), byte(i % 250)}), "x", "000000")
	}
	if !strings.Contains(msg, "для всіх") {
		t.Fatalf("global: %q", msg)
	}
	if _, _, _, err := f.a.Login(netip.MustParseAddr("10.77.0.200"), "pass-pass-pass", f.code(0)); err != errLoginBlocked {
		t.Fatalf("global lock: %v", err)
	}
}

func TestAdminSetValidation(t *testing.T) {
	au, _ := NewAdminAuth(nil)
	if au.Configured() {
		t.Fatal("configured")
	}
	if _, _, _, err := au.Login(netip.MustParseAddr("10.0.0.1"), "x", "123456"); err != errNotSetup {
		t.Fatal(err)
	}
	sec, _ := newTOTPSecret()
	if au.Set("plain", sec) == nil || au.Set(dummyHash, "!!") == nil || au.Set(dummyHash, "AAAA") == nil {
		t.Fatal("validation")
	}
}

// Паралельні спроби з однієї адреси: проходить лише одна, решта — «зачекайте».
func TestAdminLoginParallelSlot(t *testing.T) {
	f := newAuthFixture(t)
	ip := netip.MustParseAddr("10.77.0.20")
	res := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func() { _, _, _, err := f.a.Login(ip, "wrong-wrong", "000000"); res <- err }()
	}
	bad := 0
	for i := 0; i < 8; i++ {
		if <-res == errLoginBad {
			bad++
		}
	}
	if bad != 1 {
		t.Fatalf("checked %d passwords in parallel, want 1", bad)
	}
}

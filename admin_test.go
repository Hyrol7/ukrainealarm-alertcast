package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAdminSocketRoundTrip(t *testing.T) {
	ta := newTestApp(t)
	sock := filepath.Join(ta.dir, "admin.sock")
	ln, err := listenAdmin(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go ta.serveAdmin(ln)
	if fi, _ := os.Stat(sock); fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v", fi.Mode().Perm())
	}
	add, err := adminCall(sock, adminReq{Op: "add", Spec: TokenSpec{Name: ptr("лампа"), Regions: &[]string{"10"}, RPM: ptr(30),
		Streams: ptr(1), Nets: &[]string{"10.77.0.0/24", "10.77.0.8"}, AllowQuery: ptr(true)}})
	if err != nil || !looksLikeToken(add.Secret) || add.Token.ID == "" {
		t.Fatalf("add: %v %+v", err, add)
	}
	i := add.Token
	if i.RPM != 30 || i.Streams != 1 || strings.Join(i.Nets, ",") != "10.77.0.0/24,10.77.0.8/32" || !i.AllowQuery {
		t.Fatalf("spec: %+v", i)
	}
	// помилки валідації — відмова, токен не створюється
	for _, sp := range []TokenSpec{
		{},                  // без назви
		{Name: ptr("")},     // порожня
		{Name: ptr("a\nb")}, // керівні
		{Name: ptr("x"), Regions: &[]string{"99999"}},
		{Name: ptr("x"), Regions: &[]string{"1;DROP"}},
		{Name: ptr("x"), Nets: &[]string{"300.1.1.1"}},
		{Name: ptr("x"), RPM: ptr(0)},
		{Name: ptr("x"), Streams: ptr(-1)},
		{Name: ptr(strings.Repeat("я", 65))},
	} {
		if _, err := adminCall(sock, adminReq{Op: "add", Spec: sp}); err == nil {
			t.Fatalf("invalid spec accepted: %+v", sp)
		}
	}
	list, _ := adminCall(sock, adminReq{Op: "list"})
	if len(list.Tokens) != 1 {
		t.Fatalf("list: %d", len(list.Tokens))
	}
	if _, err := adminCall(sock, adminReq{Op: "show", ID: "nope"}); err == nil {
		t.Fatal("show unknown")
	}
	if _, err := adminCall(sock, adminReq{Op: "drop-tables"}); err == nil {
		t.Fatal("unknown op")
	}
	// використання, потім статистика переживає перезапуск сховища
	if r := do(t, ta.vpn.URL, "/api/v1/status", add.Secret, "X-Forwarded-For", "10.77.0.8"); r.code != 200 {
		t.Fatalf("use: %d %s", r.code, r.body)
	}
	ta.tokens.FlushStats()
	raw, _ := os.ReadFile(filepath.Join(ta.dir, "ac.db"))
	wal, _ := os.ReadFile(filepath.Join(ta.dir, "ac.db-wal"))
	if bytes.Contains(raw, []byte(add.Secret)) || bytes.Contains(wal, []byte(add.Secret)) ||
		bytes.Contains(raw, []byte(add.Secret[3:])) || bytes.Contains(wal, []byte(add.Secret[3:])) {
		t.Fatal("raw token stored in the database")
	}
	t2, err := OpenTokens(filepath.Join(ta.dir, "ac.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer t2.Close()
	got, ok := t2.Get(i.ID)
	if !ok || got.Requests != 1 || got.LastIP != "10.77.0.8" || got.Name != "лампа" {
		t.Fatalf("persisted: %+v", got)
	}
	if _, err := adminCall(sock, adminReq{Op: "revoke", ID: i.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := adminCall(sock, adminReq{Op: "revoke", ID: i.ID}); err == nil {
		t.Fatal("double revoke")
	}
}

func TestParseSpecFlags(t *testing.T) {
	sp, pos, err := parseSpec(flag.NewFlagSet("t", flag.ContinueOnError),
		[]string{"abcd1234", "--regions", "4, 32,", "--rpm", "10", "--ip", "", "--allow-query=false", "--expires", "never"})
	if err != nil || len(pos) != 1 || pos[0] != "abcd1234" {
		t.Fatalf("%v %v", err, pos)
	}
	if strings.Join(*sp.Regions, ",") != "4,32" || *sp.RPM != 10 || len(*sp.Nets) != 0 || *sp.AllowQuery || !sp.Expires.IsZero() {
		t.Fatalf("spec: %+v", sp)
	}
	if sp.Name != nil || sp.Streams != nil {
		t.Fatal("unset flags must stay nil (не змінювати)")
	}
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.Local)
	for in, want := range map[string]time.Time{
		"90d":        now.Add(90 * 24 * time.Hour),
		"12h":        now.Add(12 * time.Hour),
		"2027-06-01": time.Date(2027, 6, 1, 23, 59, 59, 0, time.Local),
	} {
		if got, err := parseExpires(in, now); err != nil || !got.Equal(want) {
			t.Errorf("%s: %v %v", in, got, err)
		}
	}
	for _, bad := range []string{"tomorrow", "-1d", "2027-13-01", "5y"} {
		if _, err := parseExpires(bad, now); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestTokenFormat(t *testing.T) {
	raw, h := newSecret()
	if !looksLikeToken(raw) || hashToken(raw) != h || len(raw) != 46 {
		t.Fatalf("token %q", raw)
	}
	for _, bad := range []string{"", "ac_", raw + "x", raw[:45], "xx" + raw[2:], strings.Replace(raw, raw[10:11], "!", 1)} {
		if looksLikeToken(bad) && bad != raw {
			t.Errorf("accepted %q", bad)
		}
	}
	a, _ := newSecret()
	if a == raw {
		t.Fatal("secrets repeat")
	}
}

func TestValidateConfig(t *testing.T) {
	good := testConfig()
	good.AlertdURL, good.PublicListen, good.LocalListen = "http://127.0.0.1:8788", "127.0.0.1:8790", "127.0.0.1:8792"
	if err := validateConfig(good); err != nil {
		t.Fatal(err)
	}
	for name, f := range map[string]func(*Config){
		"remote http alertd": func(c *Config) { c.AlertdURL = "http://10.0.0.5:8788" },
		"public admin":       func(c *Config) { c.AdminListen = "0.0.0.0:8793" },
		"vpn admin":          func(c *Config) { c.AdminListen = "10.77.0.1:8793" },
		"bad admin ip src":   func(c *Config) { c.AdminIPSource = "header" },
		"bad alertd":         func(c *Config) { c.AlertdURL = "ftp://127.0.0.1" },
		"public local api":   func(c *Config) { c.LocalListen = "0.0.0.0:8792" },
		"bad ip source":      func(c *Config) { c.PublicIPSource = "header" },
		"same listeners":     func(c *Config) { c.VPNListen = c.PublicListen },
		"short stale":        func(c *Config) { c.StaleAfter = time.Second },
		"zero streams":       func(c *Config) { c.MaxStreams = 0 },
		"bad cf ranges":      func(c *Config) { c.CFRanges = "1.2.3.4/99" },
		"title":              func(c *Config) { c.SiteTitle = "a\x00b" },
	} {
		c := good
		f(&c)
		if validateConfig(c) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

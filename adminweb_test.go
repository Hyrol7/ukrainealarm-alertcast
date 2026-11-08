package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type admClient struct {
	t      *testing.T
	base   string
	cookie string
	csrf   string
	origin string
}

func (c *admClient) req(method, path, body string, hdr ...string) resp {
	c.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r, _ := http.NewRequest(method, c.base+path, rd)
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if method != "GET" {
		r.Header.Set("Origin", c.origin)
	}
	if c.cookie != "" {
		r.AddCookie(&http.Cookie{Name: adminCookie, Value: c.cookie})
	}
	if c.csrf != "" {
		r.Header.Set("X-CSRF", c.csrf)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i+1] == "" {
			r.Header.Del(hdr[i])
		} else {
			r.Header.Set(hdr[i], hdr[i+1])
		}
	}
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return resp{res.StatusCode, res.Header, string(b)}
}

func newAdmin(t *testing.T) (*testApp, *admClient, *authFixture) {
	ta := newTestApp(t)
	sec, _ := newTOTPSecret()
	h, _ := hashPassword("pass-pass-pass")
	ta.admAuth.Set(h, sec)
	srv := httptest.NewServer(ta.AdminHandler())
	t.Cleanup(srv.Close)
	c := &admClient{t: t, base: srv.URL, origin: srv.URL}
	return ta, c, &authFixture{a: ta.admAuth, clk: &fakeClock{t: time.Now()}, secret: sec}
}

func (c *admClient) login(f *authFixture) {
	c.t.Helper()
	r := c.req("POST", "/api/login", `{"password":"pass-pass-pass","code":"`+f.code(0)+`"}`)
	if r.code != 200 {
		c.t.Fatalf("login: %d %s", r.code, r.body)
	}
	ck := r.hdr.Get("Set-Cookie")
	for _, want := range []string{adminCookie + "=", "HttpOnly", "Secure", "SameSite=Strict", "Path=/"} {
		if !strings.Contains(ck, want) {
			c.t.Fatalf("cookie %q lacks %s", ck, want)
		}
	}
	c.cookie = strings.SplitN(strings.TrimPrefix(ck, adminCookie+"="), ";", 2)[0]
	var v struct{ CSRF string }
	json.Unmarshal([]byte(r.body), &v)
	c.csrf = v.CSRF
}

func TestAdminWebAuth(t *testing.T) {
	ta, c, f := newAdmin(t)
	// сторінки — статика з жорстким CSP; дані — лише після входу
	if r := c.req("GET", "/", ""); r.code != 200 || !strings.Contains(r.hdr.Get("Content-Security-Policy"), "script-src 'self'") ||
		r.hdr.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("shell: %d %v", r.code, r.hdr)
	}
	for _, p := range []string{"/api/overview", "/api/tokens", "/api/metrics", "/api/journal", "/api/test", "/api/bans", "/api/regions", "/api/live"} {
		if r := c.req("GET", p, ""); r.code != 401 {
			t.Fatalf("%s without login: %d", p, r.code)
		}
	}
	var me map[string]any
	c.req("GET", "/api/me", "").json(t, &me)
	if me["authed"] != false || me["configured"] != true || me["csrf"] != nil {
		t.Fatalf("me: %v", me)
	}
	// вхід: потрібен Origin цього сайту і JSON
	body := `{"password":"pass-pass-pass","code":"` + f.code(0) + `"}`
	if r := c.req("POST", "/api/login", body, "Origin", "https://evil.example"); r.code != 403 {
		t.Fatalf("foreign origin: %d", r.code)
	}
	if r := c.req("POST", "/api/login", body, "Origin", ""); r.code != 403 {
		t.Fatalf("no origin: %d", r.code)
	}
	if r := c.req("POST", "/api/login", body, "Content-Type", "application/x-www-form-urlencoded"); r.code != 403 {
		t.Fatalf("form: %d", r.code)
	}
	if r := c.req("POST", "/api/login", body, "Sec-Fetch-Site", "cross-site"); r.code != 403 {
		t.Fatalf("cross-site: %d", r.code)
	}
	if r := c.req("POST", "/api/login", `{"password":"bad","code":"000000"}`); r.code != 401 || !strings.Contains(r.body, `"retry":1`) {
		t.Fatalf("bad login: %d %s", r.code, r.body)
	}
	if r := c.req("POST", "/api/login", body); r.code != 429 {
		t.Fatalf("too fast after failure: %d %s", r.code, r.body)
	}
	time.Sleep(1100 * time.Millisecond)
	c.login(f)
	c.req("GET", "/api/me", "").json(t, &me)
	if me["authed"] != true || me["csrf"] != c.csrf {
		t.Fatalf("me authed: %v", me)
	}
	// зміни без X-CSRF / з чужим — ні
	csrf := c.csrf
	c.csrf = ""
	if r := c.req("POST", "/api/tokens", `{"name":"x"}`); r.code != 403 {
		t.Fatalf("no csrf: %d", r.code)
	}
	c.csrf = strings.Repeat("A", 43)
	if r := c.req("DELETE", "/api/test", "{}"); r.code != 403 {
		t.Fatalf("wrong csrf: %d", r.code)
	}
	c.csrf = csrf
	if r := c.req("POST", "/api/tokens", `{"name":"x","admin":true}`); r.code != 400 {
		t.Fatalf("unknown field: %d", r.code)
	}
	if r := c.req("POST", "/api/tokens", `{"name":"`+strings.Repeat("я", 40000)+`"}`); r.code != 400 {
		t.Fatalf("huge body: %d", r.code)
	}
	if j := ta.journal.Recent(10, "login"); len(j) < 2 || !strings.Contains(j[0].Text, "Вхід") {
		t.Fatalf("journal: %+v", j)
	}
	// вихід — cookie більше не діє
	if r := c.req("POST", "/api/logout", "{}"); r.code != 200 {
		t.Fatalf("logout: %d", r.code)
	}
	if r := c.req("GET", "/api/tokens", ""); r.code != 401 {
		t.Fatalf("after logout: %d", r.code)
	}
}

func TestAdminWebTokens(t *testing.T) {
	ta, c, f := newAdmin(t)
	ta.cfg.PublicURL = "https://alerts.example"
	c.login(f)
	var cr struct {
		Token  TokenInfo
		Secret string
		QR     string
	}
	r := c.req("POST", "/api/tokens", `{"name":"Лампа кухня","regions":["101","990100"],"rpm":30,"streams":1,"expires":"30d"}`)
	r.json(t, &cr)
	if r.code != 200 || !tokenRe.MatchString(cr.Secret) || !strings.HasPrefix(cr.QR, "<svg") || cr.Token.Expires.IsZero() {
		t.Fatalf("add: %d %s", r.code, r.body)
	}
	id := cr.Token.ID
	if r := do(t, ta.pub.URL, "/api/v1/status?regions=990101", cr.Secret); r.code != 200 {
		t.Fatalf("token works: %d", r.code)
	}
	do(t, ta.pub.URL, "/api/v1/status?regions=20", cr.Secret) // 403
	var list []admTokenRow
	c.req("GET", "/api/tokens", "").json(t, &list)
	if len(list) != 1 || list[0].ID != id || list[0].Day.Req != 1 || list[0].Day.Forbid != 1 || list[0].Status != "active" {
		t.Fatalf("list: %+v", list)
	}
	st := openStream(t, ta.pub.URL, "/api/v1/stream?regions=990101", cr.Secret)
	st.next(t, time.Second)
	var det struct {
		Token   admTokenRow
		Streams []StreamInfo
		History []TokenMinute
	}
	waitFor(t, "stream", func() bool { return len(ta.hub.List(id)) == 1 })
	c.req("GET", "/api/tokens/"+id, "").json(t, &det)
	if det.Token.Open != 1 || len(det.Streams) != 1 || det.Streams[0].Listener != "public" || len(det.History) != 1 {
		t.Fatalf("detail: %+v", det)
	}
	// тестова тривога доходить до потоку токена
	if r := c.req("POST", "/api/test", `{"region":"990100","type":"AIR","level":"red"}`); r.code != 200 || !strings.Contains(r.body, `"990100"`) {
		t.Fatalf("test set: %d %s", r.code, r.body)
	}
	if e := st.next(t, 2*time.Second); e.name != "update" || !strings.Contains(e.data, `"test":true`) {
		t.Fatalf("test update: %+v", e)
	}
	var tv struct {
		Viewers []struct{ ID string }
		ResetAt int64
		Alerts  []TestAlert
	}
	c.req("GET", "/api/test", "").json(t, &tv)
	if len(tv.Viewers) != 1 || tv.Viewers[0].ID != id || len(tv.Alerts) != 1 || tv.ResetAt < time.Now().Add(59*time.Minute).Unix() {
		t.Fatalf("test view: %+v", tv)
	}
	if r := c.req("POST", "/api/test", `{"region":"101","level":"red"}`); r.code != 400 {
		t.Fatalf("real region via test: %d", r.code)
	}
	// kick, edit, rotate, revoke
	if r := c.req("POST", "/api/tokens/"+id+"/kick", "{}"); r.code != 200 || !strings.Contains(r.body, `"kicked":1`) {
		t.Fatalf("kick: %d %s", r.code, r.body)
	}
	if r := c.req("PATCH", "/api/tokens/"+id, `{"rpm":45,"expires":""}`); r.code != 200 || !strings.Contains(r.body, `"rpm":45`) || strings.Contains(r.body, `"expires"`) {
		t.Fatalf("edit: %d %s", r.code, r.body)
	}
	if r := c.req("PATCH", "/api/tokens/"+id, `{"expires":"вчора"}`); r.code != 400 {
		t.Fatalf("bad expires: %d", r.code)
	}
	var rot struct{ Secret string }
	r = c.req("POST", "/api/tokens/"+id+"/rotate", "{}")
	r.json(t, &rot)
	if r.code != 200 || rot.Secret == cr.Secret || !tokenRe.MatchString(rot.Secret) {
		t.Fatalf("rotate: %s", r.body)
	}
	if do(t, ta.pub.URL, "/api/v1/me", cr.Secret).code != 401 || do(t, ta.pub.URL, "/api/v1/me", rot.Secret).code != 200 {
		t.Fatal("rotate effect")
	}
	if r := c.req("DELETE", "/api/tokens/"+id, "{}"); r.code != 200 {
		t.Fatalf("revoke: %d %s", r.code, r.body)
	}
	if r := c.req("GET", "/api/tokens/"+id, ""); r.code != 404 {
		t.Fatalf("after revoke: %d", r.code)
	}
	if do(t, ta.pub.URL, "/api/v1/me", rot.Secret).code != 401 {
		t.Fatal("revoked token works")
	}
	kinds := map[string]int{}
	for _, e := range ta.journal.Recent(50, "") {
		kinds[e.Kind]++
		if e.Kind == "token" && e.IP == "" {
			t.Fatalf("no actor: %+v", e)
		}
	}
	if kinds["token"] < 5 || kinds["test"] < 1 {
		t.Fatalf("journal kinds: %v", kinds)
	}
}

// Пароль і 2FA змінюються лише з сокета (root); виклик від імені веб-адміна відхиляється.
func TestAdminSetOnlyFromSocket(t *testing.T) {
	ta, _, _ := newAdmin(t)
	sec, _ := newTOTPSecret()
	h, _ := hashPassword("other-other-other")
	if r := ta.admin(adminReq{Op: "admin-set", PwHash: h, Secret: sec, Actor: "10.77.0.3"}); r.OK {
		t.Fatal("admin-set accepted from web actor")
	}
	if r := ta.admin(adminReq{Op: "admin-set", PwHash: h, Secret: sec}); !r.OK {
		t.Fatalf("socket admin-set: %s", r.Error)
	}
	var req adminReq
	json.Unmarshal([]byte(`{"op":"admin-set","Actor":"x","actor":"x"}`), &req)
	if req.Actor != "" {
		t.Fatal("Actor settable via JSON")
	}
}

func TestAdminWebMonitoring(t *testing.T) {
	ta, c, f := newAdmin(t)
	ta.fake.push("10", "AIR", lv("Red", 0))
	c.login(f)
	var ov map[string]any
	r := c.req("GET", "/api/overview", "")
	r.json(t, &ov)
	if r.code != 200 || ov["version"] != version || ov["source"].(map[string]any)["connected"] != true {
		t.Fatalf("overview: %s", r.body)
	}
	if r := c.req("GET", "/api/metrics", ""); r.code != 200 || !strings.Contains(r.body, `"minutes"`) {
		t.Fatalf("metrics: %s", r.body)
	}
	var regs []Region
	c.req("GET", "/api/regions", "").json(t, &regs)
	if len(regs) != ta.state.Tree().Len() || regs[len(regs)-1].ID == "" {
		t.Fatalf("regions: %d", len(regs))
	}
	// блокування видно й можна зняти
	for i := 0; i < ta.cfg.AuthFailLimit; i++ {
		do(t, ta.pub.URL, "/api/v1/me", "ac_bad", "X-Forwarded-For", "203.0.113.7")
	}
	var bans []Ban
	c.req("GET", "/api/bans", "").json(t, &bans)
	if len(bans) != 1 {
		t.Fatalf("bans: %+v", bans)
	}
	if r := c.req("POST", "/api/unban", `{"ip":"`+bans[0].IP+`"}`); r.code != 200 {
		t.Fatalf("unban: %d %s", r.code, r.body)
	}
	if r := c.req("POST", "/api/unban", `{"ip":"`+bans[0].IP+`"}`); r.code != 404 {
		t.Fatalf("unban twice: %d", r.code)
	}
	// наживо: огляд одразу, і потік закривається після виходу
	st := openAdminLive(t, c)
	if e := st.next(t, time.Second); e.name != "overview" {
		t.Fatalf("live: %+v", e)
	}
	c.req("POST", "/api/logout", "{}")
	for {
		e := st.next(t, 5*time.Second)
		if e.name == "logout" {
			break
		}
	}
}

func openAdminLive(t *testing.T, c *admClient) *sseClient {
	t.Helper()
	return openStreamWith(t, c.base+"/api/live", func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: adminCookie, Value: c.cookie})
	})
}

// Порожній стан: жодних null замість масивів (сторінки читають .length).
func TestAdminWebEmptyArrays(t *testing.T) {
	_, c, f := newAdmin(t)
	c.login(f)
	for _, p := range []string{"/api/bans", "/api/tokens", "/api/journal?kind=none", "/api/regions"} {
		if r := c.req("GET", p, ""); r.code != 200 || !strings.HasPrefix(r.body, "[") {
			t.Fatalf("%s: %s", p, r.body)
		}
	}
	for p, field := range map[string]string{"/api/metrics": `"minutes":[`, "/api/test": `"alerts":[`} {
		if r := c.req("GET", p, ""); !strings.Contains(r.body, field) {
			t.Fatalf("%s: %s", p, r.body)
		}
	}
	var tk struct{ Token TokenInfo }
	c.req("POST", "/api/tokens", `{"name":"x"}`).json(t, &tk)
	if r := c.req("GET", "/api/tokens/"+tk.Token.ID, ""); !strings.Contains(r.body, `"history":[`) || !strings.Contains(r.body, `"streams":[`) {
		t.Fatalf("token: %s", r.body)
	}
}

func TestAdminWebIdleAndMe(t *testing.T) {
	ta, c, f := newAdmin(t)
	var me map[string]any
	c.req("GET", "/api/me", "").json(t, &me)
	if _, ok := me["version"]; ok || me["ip"] != nil {
		t.Fatalf("me before login reveals: %v", me)
	}
	c.login(f)
	clk := &fakeClock{t: time.Now()}
	ta.admAuth.now = clk.now
	// фонові запити 40 хв — сесія все одно гасне за 30 хв простою
	for i := 0; i < 4; i++ {
		clk.t = clk.t.Add(10 * time.Minute)
		r := c.req("GET", "/api/overview", "", "X-Background", "1")
		if (i < 2) != (r.code == 200) {
			t.Fatalf("background step %d: %d", i, r.code)
		}
	}
	if r := c.req("GET", "/api/overview", "", "X-Background", "1"); r.code != 401 {
		t.Fatalf("idle session alive: %d", r.code)
	}
	if r := c.req("GET", "/", ""); r.hdr.Get("Strict-Transport-Security") == "" {
		t.Fatal("no HSTS")
	}
}

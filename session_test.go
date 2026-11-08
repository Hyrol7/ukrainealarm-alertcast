package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func reqSession(t *testing.T, method, url string, hdr ...string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	return res, string(b)
}

func login(t *testing.T, ta *testApp, tok string) string {
	t.Helper()
	res, body := reqSession(t, "POST", ta.pub.URL+"/api/v1/session", "Authorization", "Bearer "+tok)
	if res.StatusCode != 200 {
		t.Fatalf("login: %d %s", res.StatusCode, body)
	}
	for _, c := range res.Cookies() {
		if c.Name == sessionCookie {
			return c.Value
		}
	}
	t.Fatal("no session cookie")
	return ""
}

func TestSessionCookieAttributes(t *testing.T) {
	ta := newTestApp(t)
	tok, _ := ta.token(t)
	res, _ := reqSession(t, "POST", ta.pub.URL+"/api/v1/session", "Authorization", "Bearer "+tok)
	sc := res.Header.Get("Set-Cookie")
	for _, want := range []string{"__Host-ac_session=", "Path=/", "HttpOnly", "Secure", "SameSite=Strict", "Max-Age=43200"} {
		if !strings.Contains(sc, want) {
			t.Fatalf("cookie lacks %q: %s", want, sc)
		}
	}
	if strings.Contains(strings.ToLower(sc), "domain=") {
		t.Fatal("__Host- cookie must not have Domain")
	}
}

func TestSessionWorksAndIsRevoked(t *testing.T) {
	ta := newTestApp(t)
	tok, info := ta.token(t, func(s *TokenSpec) { s.Regions = &[]string{"10"} })
	sid := login(t, ta, tok)
	ck := sessionCookie + "=" + sid
	if r := do(t, ta.pub.URL, "/api/v1/status?regions=101", "", "Cookie", ck); r.code != 200 {
		t.Fatalf("status via cookie: %d %s", r.code, r.body)
	}
	if r := do(t, ta.pub.URL, "/api/v1/status?regions=2", "", "Cookie", ck); r.code != 403 {
		t.Fatalf("session keeps token's region scope: %d", r.code)
	}
	// потік через cookie (EventSource так і працює)
	req, _ := http.NewRequestWithContext(t.Context(), "GET", ta.pub.URL+"/api/v1/stream?regions=10", nil)
	req.Header.Set("Cookie", ck)
	res, err := http.DefaultClient.Do(req)
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("stream via cookie: %v %d", err, res.StatusCode)
	}
	res.Body.Close()
	// зміна токена гасить сесії
	ta.admin(adminReq{Op: "edit", ID: info.ID, Spec: TokenSpec{RPM: ptr(100)}})
	if r := do(t, ta.pub.URL, "/api/v1/me", "", "Cookie", ck); r.code != 401 {
		t.Fatalf("session after token edit: %d", r.code)
	}
	sid2 := login(t, ta, tok)
	ta.admin(adminReq{Op: "revoke", ID: info.ID})
	if r := do(t, ta.pub.URL, "/api/v1/me", "", "Cookie", sessionCookie+"="+sid2); r.code != 401 {
		t.Fatalf("session after revoke: %d", r.code)
	}
	if ta.sessions.Len() != 0 {
		t.Fatalf("sessions left: %d", ta.sessions.Len())
	}
}

func TestSessionLoginRules(t *testing.T) {
	ta := newTestApp(t)
	q, _ := ta.token(t, func(s *TokenSpec) { s.AllowQuery = ptr(true) })
	vpnOnly, _ := ta.token(t, func(s *TokenSpec) { s.Nets = &[]string{"10.77.0.0/24"} })
	// вхід лише токеном із заголовка: не з адреси, не cookie-сесією
	if res, _ := reqSession(t, "POST", ta.pub.URL+"/api/v1/session?token="+q); res.StatusCode != 401 {
		t.Fatalf("login via query: %d", res.StatusCode)
	}
	sid := login(t, ta, q)
	if res, _ := reqSession(t, "POST", ta.pub.URL+"/api/v1/session", "Cookie", sessionCookie+"="+sid); res.StatusCode != 401 {
		t.Fatalf("login via session cookie: %d", res.StatusCode)
	}
	// чужий Origin — відмова (захист від входу з чужого сайту)
	if res, _ := reqSession(t, "POST", ta.pub.URL+"/api/v1/session", "Authorization", "Bearer "+q, "Origin", "https://evil.example"); res.StatusCode != 403 {
		t.Fatalf("cross-origin login: %d", res.StatusCode)
	}
	// обмеження за адресою діє і для сесії
	res, _ := reqSession(t, "POST", ta.vpn.URL+"/api/v1/session", "Authorization", "Bearer "+vpnOnly, "X-Forwarded-For", "10.77.0.4")
	if res.StatusCode != 200 {
		t.Fatalf("vpn login: %d", res.StatusCode)
	}
	vsid := res.Cookies()[0].Value
	if r := do(t, ta.pub.URL, "/api/v1/me", "", "Cookie", sessionCookie+"="+vsid, "X-Forwarded-For", "172.64.1.1", "Cf-Connecting-Ip", "203.0.113.8"); r.code != 401 {
		t.Fatalf("session from another network: %d", r.code)
	}
	// підроблена cookie — 401 і рахується як невдала спроба
	n := ta.reqDenied.Load()
	if r := do(t, ta.pub.URL, "/api/v1/me", "", "Cookie", sessionCookie+"="+strings.Repeat("A", 43)); r.code != 401 || ta.reqDenied.Load() != n+1 {
		t.Fatalf("forged cookie: %d", r.code)
	}
	// вихід
	res, _ = reqSession(t, "DELETE", ta.pub.URL+"/api/v1/session", "Cookie", sessionCookie+"="+sid)
	if res.StatusCode != 200 || !strings.Contains(res.Header.Get("Set-Cookie"), "Max-Age=0") {
		t.Fatalf("logout: %d %s", res.StatusCode, res.Header.Get("Set-Cookie"))
	}
	if r := do(t, ta.pub.URL, "/api/v1/me", "", "Cookie", sessionCookie+"="+sid); r.code != 401 {
		t.Fatalf("session after logout: %d", r.code)
	}
	if res, _ := reqSession(t, "PUT", ta.pub.URL+"/api/v1/session"); res.StatusCode != 405 {
		t.Fatalf("PUT session: %d", res.StatusCode)
	}
	if res, _ := reqSession(t, "POST", ta.pub.URL+"/api/v1/status"); res.StatusCode != 405 {
		t.Fatalf("POST elsewhere: %d", res.StatusCode)
	}
}

func TestSessionLimitsAndExpiry(t *testing.T) {
	s := NewSessions()
	now := time.Now()
	s.now = func() time.Time { return now }
	tk := &token{TokenInfo: TokenInfo{ID: "t1"}}
	var first string
	for i := 0; i < maxSessionsTok+5; i++ {
		id, _, ok := s.Create(tk)
		if !ok {
			t.Fatal("create")
		}
		if i == 0 {
			first = id
		}
		now = now.Add(time.Second)
	}
	if s.Len() != maxSessionsTok || s.Get(first) != nil {
		t.Fatalf("per-token cap: %d, oldest kept: %v", s.Len(), s.Get(first) != nil)
	}
	last, _, _ := s.Create(tk)
	if s.Get(last) == nil {
		t.Fatal("fresh session")
	}
	now = now.Add(sessionTTL + time.Minute)
	if s.Get(last) != nil { // прострочена — відмова одразу, без очікування прибирання
		t.Fatal("expired session accepted")
	}
	s.GC()
	if s.Len() != 0 {
		t.Fatalf("expired sessions: %d", s.Len())
	}
	if s.Get("short") != nil {
		t.Fatal("bad id")
	}
}

// Другий шар: навіть якщо сесії токена не прибрано (зміна не через адмін-команду), сесія
// зміненого токена не працює — перевіряється, що токен досі той самий.
func TestSessionOfReplacedTokenRejected(t *testing.T) {
	ta := newTestApp(t)
	tok, info := ta.token(t)
	sid := login(t, ta, tok)
	if _, _, err := ta.tokens.Edit(info.ID, TokenSpec{RPM: ptr(5)}, ta.state.Tree(), false); err != nil {
		t.Fatal(err)
	}
	if r := do(t, ta.pub.URL, "/api/v1/me", "", "Cookie", sessionCookie+"="+sid); r.code != 401 {
		t.Fatalf("stale session accepted: %d", r.code)
	}
}

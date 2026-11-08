package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// cf — заголовки запиту, що прийшов через Cloudflare (Caddy ставить X-Forwarded-For = вузол CF).
func cf(ip string) []string {
	return []string{"X-Forwarded-For", "172.64.10.20", "Cf-Connecting-Ip", ip}
}

// ---------- зв'язок з alertd ----------

func TestSourceFollowsAlertd(t *testing.T) {
	ta := newTestApp(t)
	ta.fake.push("10", "AIR", lv("Red", 0))
	waitFor(t, "start", func() bool { return ta.state.Status("100").State == "active" })
	ta.fake.push("10", "AIR", lv("Yellow", 1))
	waitFor(t, "update", func() bool { return ta.state.Status("100").Level == "yellow" })
	ta.fake.push("10", "AIR")
	waitFor(t, "end", func() bool { return ta.state.Status("100").State == "none" })
}

// Обрив потоку: alertcast перепідключається з Last-Event-ID і отримує пропущене.
func TestSourceReconnectCatchesUp(t *testing.T) {
	ta := newTestApp(t)
	ta.fake.push("10", "AIR", lv("Red", 0))
	waitFor(t, "first", func() bool { return ta.state.Status("10").State == "active" })
	ta.fake.dropAll()
	ta.fake.push("20", "AIR", lv("Red", 0)) // поки потоку немає
	waitFor(t, "missed event after reconnect", func() bool { return ta.state.Status("20").State == "active" })
	if ta.src.resyncs.Load() != 0 {
		t.Fatal("plain reconnect must not need a full resync")
	}
}

// Нова БД alertd (інший epoch) — повне перечитування знімка, а не довіра старому seq.
func TestSourceEpochChangeResyncs(t *testing.T) {
	ta := newTestApp(t)
	ta.fake.push("10", "AIR", lv("Red", 0))
	waitFor(t, "first", func() bool { return ta.state.Status("10").State == "active" })
	ta.fake.mu.Lock()
	ta.fake.active = map[string]stateItem{"21|AIR": {RegionID: "21", AlarmType: "AIR", Active: []Level{lv("Yellow", 0)}}}
	ta.fake.mu.Unlock()
	ta.fake.newDB("e2")
	waitFor(t, "state from new db", func() bool {
		return ta.state.Status("10").State == "none" && ta.state.Status("21").State == "active"
	})
	if ta.src.resyncs.Load() == 0 {
		t.Fatal("epoch change must resync")
	}
}

func TestSourceResyncEvent(t *testing.T) {
	ta := newTestApp(t)
	ta.fake.mu.Lock()
	ta.fake.active["11|AIR"] = stateItem{RegionID: "11", AlarmType: "AIR", Active: []Level{lv("Red", 0)}}
	ta.fake.mu.Unlock()
	ta.fake.send("event: resync\ndata: {}\n\n")
	waitFor(t, "resync reload", func() bool { return ta.state.Status("11").State == "active" })
}

// alertd мовчить (навіть без ping) — watchdog рве з'єднання і перепідключається.
func TestSourceIdleWatchdog(t *testing.T) {
	ta := newTestApp(t)
	n0 := ta.fake.conns.Load()
	ta.fake.silent.Store(true)
	waitFor(t, "reconnect after idle", func() bool { return ta.fake.conns.Load() > n0 })
}

// alertd недоступний: стан лишається, але позначається stale; після повернення — свіжий.
func TestStaleWhenAlertdDown(t *testing.T) {
	ta := newTestApp(t, func(c *Config, s *Source) { s.downGrace = 300 * time.Millisecond })
	tok, _ := ta.token(t)
	ta.fake.push("10", "AIR", lv("Red", 0))
	waitFor(t, "alert", func() bool { return ta.state.Status("10").State == "active" })
	st := openStream(t, ta.pub.URL, "/api/v1/stream?regions=10", tok)
	if e := st.next(t, time.Second); e.name != "snapshot" || strings.Contains(e.data, `"stale":true`) {
		t.Fatalf("snapshot: %+v", e)
	}
	ta.fake.down.Store(true)
	ta.fake.dropAll()
	waitFor(t, "stale", func() bool { s, _ := ta.src.Fresh(time.Now()); return s })
	var r statusResp
	do(t, ta.pub.URL, "/api/v1/status?regions=10", tok).json(t, &r)
	if !r.Stale || r.Regions["10"].State != "active" {
		t.Fatalf("stale response must keep last state: %+v", r)
	}
	if e := st.next(t, 3*time.Second); e.name != "meta" || !strings.Contains(e.data, `"stale":true`) {
		t.Fatalf("stream meta: %+v", e)
	}
	ta.fake.down.Store(false)
	waitFor(t, "fresh again", func() bool { s, _ := ta.src.Fresh(time.Now()); return !s })
	if e := st.next(t, 3*time.Second); e.name != "meta" || !strings.Contains(e.data, `"stale":false`) {
		t.Fatalf("stream meta fresh: %+v", e)
	}
}

// alertd давно не звіряв стан з API ukrainealarm — дані позначаються застарілими.
func TestStaleWhenAlertdNotVerified(t *testing.T) {
	ta := newTestApp(t, func(c *Config, s *Source) { s.staleAfter = time.Minute })
	ta.fake.lastSync.Store(time.Now().Add(-2 * time.Minute).Unix())
	waitFor(t, "stale by verification age", func() bool { s, _ := ta.src.Fresh(time.Now()); return s })
}

// ---------- автентифікація ----------

func TestAuthUniform401(t *testing.T) {
	ta := newTestApp(t)
	good, _ := ta.token(t)
	expired, _ := ta.token(t, func(s *TokenSpec) { s.Expires = ptr(time.Now().Add(-time.Second)) })
	vpnOnly, _ := ta.token(t, func(s *TokenSpec) { s.Nets = &[]string{"10.77.0.0/24"} })
	cases := map[string]func() resp{
		"no token":       func() resp { return do(t, ta.pub.URL, "/api/v1/me", "") },
		"garbage":        func() resp { return do(t, ta.pub.URL, "/api/v1/me", "abc") },
		"wrong secret":   func() resp { return do(t, ta.pub.URL, "/api/v1/me", good[:len(good)-1]+"x") },
		"expired":        func() resp { return do(t, ta.pub.URL, "/api/v1/me", expired) },
		"wrong ip":       func() resp { return do(t, ta.pub.URL, "/api/v1/me", vpnOnly, cf("203.0.113.5")...) },
		"query disallow": func() resp { return do(t, ta.pub.URL, "/api/v1/me?token="+good, "") },
		"unknown path":   func() resp { return do(t, ta.pub.URL, "/api/v1/secret", "") },
		"v3 no token":    func() resp { return do(t, ta.pub.URL, "/api/v3/alerts", "") },
	}
	var bodies []string
	for name, f := range cases {
		r := f()
		if r.code != 401 || r.hdr.Get("Content-Type") != "application/json; charset=utf-8" {
			t.Fatalf("%s: %d %s", name, r.code, r.body)
		}
		bodies = append(bodies, r.body)
	}
	for _, b := range bodies {
		if b != bodies[0] {
			t.Fatalf("401 bodies differ: %q vs %q", b, bodies[0])
		}
	}
	if r := do(t, ta.pub.URL, "/api/v1/me", good); r.code != 200 {
		t.Fatalf("good token: %d %s", r.code, r.body)
	}
	if r := do(t, ta.vpn.URL, "/api/v1/me", vpnOnly, "X-Forwarded-For", "10.77.0.7"); r.code != 200 {
		t.Fatalf("vpn token from vpn ip: %d", r.code)
	}
	// формати передачі: Bearer, як в ukrainealarm (без префікса), X-API-Key
	for _, h := range [][]string{{"Authorization", good}, {"X-Api-Key", good}, {"Authorization", "bearer " + good}} {
		if r := do(t, ta.pub.URL, "/api/v1/me", "", h...); r.code != 200 {
			t.Fatalf("header %s: %d", h[0], r.code)
		}
	}
}

func TestQueryTokenOnlyWhenAllowed(t *testing.T) {
	ta := newTestApp(t)
	q, _ := ta.token(t, func(s *TokenSpec) { s.AllowQuery = ptr(true) })
	if r := do(t, ta.pub.URL, "/api/v1/me?token="+q, ""); r.code != 200 {
		t.Fatalf("query token with permission: %d", r.code)
	}
	// VPN-вхід: журнал proxy пише адресу повністю — токен у адресі там не приймається взагалі
	if r := do(t, ta.vpn.URL, "/api/v1/me?token="+q, "", "X-Forwarded-For", "10.77.0.7"); r.code != 401 {
		t.Fatalf("query token on vpn listener: %d", r.code)
	}
	if r := do(t, ta.vpn.URL, "/api/v1/me", q, "X-Forwarded-For", "10.77.0.7"); r.code != 200 {
		t.Fatalf("header token on vpn listener: %d", r.code)
	}
}

// Справжня адреса клієнта: заголовкам вірити лише від локального proxy; VPN-вхід не вірить
// CF-Connecting-IP (його міг би підставити будь-хто з VPN).
func TestClientIPTrust(t *testing.T) {
	mk := func(remote string, h ...string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		for i := 0; i+1 < len(h); i += 2 {
			r.Header.Add(h[i], h[i+1])
		}
		return r
	}
	const cfNode = "172.64.10.20"
	cases := []struct {
		src  string
		req  *http.Request
		want string
	}{
		// публічний вхід через Cloudflare: справжній клієнт — у CF-Connecting-IP
		{ipCF, mk("127.0.0.1:5000", "X-Forwarded-For", cfNode, "Cf-Connecting-Ip", "198.51.100.7"), "198.51.100.7"},
		{ipCF, mk("127.0.0.1:5000", "X-Forwarded-For", "2606:4700::1", "Cf-Connecting-Ip", "2001:db8::5"), "2001:db8::5"},
		// той самий публічний сайт через VPN: CF-Connecting-IP підставив клієнт — ігнорується
		{ipCF, mk("127.0.0.1:5000", "X-Forwarded-For", "10.77.0.5", "Cf-Connecting-Ip", "198.51.100.7"), "10.77.0.5"},
		// клієнт підсунув власний X-Forwarded-For з адресою CF — proxy дописує справжню останньою
		{ipCF, mk("127.0.0.1:5000", "X-Forwarded-For", cfNode+", 10.77.0.5", "Cf-Connecting-Ip", "1.1.1.1"), "10.77.0.5"},
		{ipCF, mk("127.0.0.1:5000", "X-Forwarded-For", cfNode, "Cf-Connecting-Ip", "not-an-ip"), cfNode},
		{ipCF, mk("127.0.0.1:5000", "Cf-Connecting-Ip", "198.51.100.7"), "127.0.0.1"},                           // без proxy-заголовка — не віримо
		{ipCF, mk("203.0.113.9:5000", "X-Forwarded-For", cfNode, "Cf-Connecting-Ip", "1.1.1.1"), "203.0.113.9"}, // не від локального proxy
		// VPN-вхід: адреса в тунелі, CF-заголовок не діє
		{ipXFF, mk("127.0.0.1:5000", "X-Forwarded-For", "6.6.6.6, 10.77.0.5"), "10.77.0.5"},
		{ipXFF, mk("127.0.0.1:5000", "X-Forwarded-For", "6.6.6.6", "X-Forwarded-For", "10.77.0.9"), "10.77.0.9"},
		{ipXFF, mk("127.0.0.1:5000", "X-Forwarded-For", cfNode, "Cf-Connecting-Ip", "10.77.0.5"), cfNode},
		{ipXFF, mk("10.77.0.3:5000", "X-Forwarded-For", "10.77.0.5"), "10.77.0.3"},
		{ipRemote, mk("[::ffff:127.0.0.1]:1", "X-Forwarded-For", cfNode, "Cf-Connecting-Ip", "1.2.3.4"), "127.0.0.1"},
	}
	for i, c := range cases {
		if got := clientIP(c.req, c.src).String(); got != c.want {
			t.Errorf("case %d (%s): %s, want %s", i, c.src, got, c.want)
		}
	}
}

func TestRateLimits(t *testing.T) {
	ta := newTestApp(t)
	tok, _ := ta.token(t, func(s *TokenSpec) { s.RPM = ptr(6) }) // сплеск 3
	codes := []int{}
	for i := 0; i < 5; i++ {
		codes = append(codes, do(t, ta.pub.URL, "/api/v1/me", tok).code)
	}
	if fmt.Sprint(codes) != "[200 200 200 429 429]" {
		t.Fatalf("token bucket: %v", codes)
	}
	r := do(t, ta.pub.URL, "/api/v1/me", tok)
	if r.code != 429 || r.hdr.Get("Retry-After") == "" {
		t.Fatalf("429 must carry Retry-After: %v", r.hdr)
	}
	// інший токен з тієї ж адреси не страждає
	other, _ := ta.token(t)
	if r := do(t, ta.pub.URL, "/api/v1/me", other); r.code != 200 {
		t.Fatalf("other token: %d", r.code)
	}
}

// Після серії невдалих спроб адреса блокується — навіть з правильним токеном; інші адреси — ні.
func TestBruteForceBan(t *testing.T) {
	ta := newTestApp(t)
	good, _ := ta.token(t)
	attacker := cf("198.51.100.66")
	for i := 0; i < ta.cfg.AuthFailLimit; i++ {
		if r := do(t, ta.pub.URL, "/api/v1/me", "ac_wrong", attacker...); r.code != 401 {
			t.Fatalf("attempt %d: %d", i, r.code)
		}
	}
	if r := do(t, ta.pub.URL, "/api/v1/me", good, attacker...); r.code != 429 {
		t.Fatalf("banned ip must get 429: %d", r.code)
	}
	if r := do(t, ta.pub.URL, "/api/v1/me", good, cf("198.51.100.67")...); r.code != 200 {
		t.Fatalf("other ip: %d", r.code)
	}
	// IPv6: блокується вся /64 (одна «людина»)
	for i := 0; i < ta.cfg.AuthFailLimit; i++ {
		do(t, ta.pub.URL, "/api/v1/me", "x", cf(fmt.Sprintf("2001:db8:1:2::%x", i+1))...)
	}
	if r := do(t, ta.pub.URL, "/api/v1/me", good, cf("2001:db8:1:2::ffff")...); r.code != 429 {
		t.Fatalf("ipv6 /64 ban: %d", r.code)
	}
	if ta.guard.bans.Load() != 2 {
		t.Fatalf("bans: %d", ta.guard.bans.Load())
	}
}

func TestIPGuardMemoryBounded(t *testing.T) {
	g := newIPGuard(100, 10, time.Minute, time.Minute)
	g.maxEntries = 100
	now := time.Now()
	for i := 0; i < 300; i++ {
		g.allow(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}), now)
	}
	if g.size() > 100 {
		t.Fatalf("guard grew to %d", g.size())
	}
	g.gc(now.Add(time.Hour))
	if g.size() != 0 {
		t.Fatalf("gc: %d", g.size())
	}
}

// ---------- запити ----------

func TestStatusEndpoint(t *testing.T) {
	ta := newTestApp(t)
	tok, _ := ta.token(t)
	ta.fake.push("10", "AIR", lv("Red", 0))
	waitFor(t, "alert", func() bool { return ta.state.Status("10").State == "active" })
	var r statusResp
	res := do(t, ta.pub.URL, "/api/v1/status?regions=101,1,11", tok)
	res.json(t, &r)
	if res.code != 200 || r.Stale || r.Regions["101"].State != "active" || r.Regions["1"].State != "partial" || r.Regions["11"].State != "none" {
		t.Fatalf("status: %d %s", res.code, res.body)
	}
	for _, c := range []struct {
		q    string
		code int
	}{
		{"", 400}, {"?regions=", 400}, {"?regions=abc", 400}, {"?regions=99999", 400},
		{"?regions=" + strings.Repeat("1,", 65) + "2", 200}, // дублікати схлопуються
		{"?regions=" + strings.Repeat("x", 5000), 400},
	} {
		if r := do(t, ta.pub.URL, "/api/v1/status"+c.q, tok); r.code != c.code || !strings.Contains(r.body, `"ok":`) {
			t.Errorf("%q: %d %s", c.q, r.code, r.body)
		}
	}
	ta.cfg.MaxRegions = 3
	if r := do(t, ta.pub.URL, "/api/v1/status?regions=1,2,10,11", tok); r.code != 400 || !strings.Contains(r.body, "at most 3") {
		t.Fatalf("too many regions: %d %s", r.code, r.body)
	}
}

func TestRegionScope(t *testing.T) {
	ta := newTestApp(t)
	tok, _ := ta.token(t, func(s *TokenSpec) { s.Regions = &[]string{"10"} })
	if r := do(t, ta.pub.URL, "/api/v1/status?regions=101", tok); r.code != 200 {
		t.Fatalf("descendant allowed: %d", r.code)
	}
	for _, id := range []string{"1", "11", "110", "2"} { // предок, сусід, інша область
		if r := do(t, ta.pub.URL, "/api/v1/status?regions="+id, tok); r.code != 403 {
			t.Fatalf("region %s: %d", id, r.code)
		}
	}
	// без параметра — регіони токена
	var r statusResp
	do(t, ta.pub.URL, "/api/v1/status", tok).json(t, &r)
	if len(r.Regions) != 1 || r.Regions["10"].ID != "10" {
		t.Fatalf("default regions: %+v", r.Regions)
	}
	// v3: лише дозволене
	ta.fake.push("1", "AIR", lv("Red", 0))
	ta.fake.push("21", "AIR", lv("Red", 0))
	waitFor(t, "alerts", func() bool { return ta.state.ActiveCount() == 2 })
	var recs []v3Record
	do(t, ta.pub.URL, "/api/v3/alerts", tok).json(t, &recs)
	for _, rec := range recs {
		if !ta.state.Tree().Within(rec.RegionID, "10") {
			t.Fatalf("v3 leaked region %s", rec.RegionID)
		}
	}
	if len(recs) != 4 { // 10 і три громади (тривога області в їхніх записах)
		t.Fatalf("v3 records: %d", len(recs))
	}
	if r := do(t, ta.pub.URL, "/api/v3/alerts/21", tok); r.code != 403 {
		t.Fatalf("v3 one forbidden: %d", r.code)
	}
}

func TestV3Endpoints(t *testing.T) {
	ta := newTestApp(t)
	tok, _ := ta.token(t)
	ta.fake.push("10", "AIR", lv("Red", 0))
	waitFor(t, "alert", func() bool { return ta.state.ActiveCount() == 1 })
	var one []v3Record
	do(t, ta.pub.URL, "/api/v3/alerts/101", "", "Authorization", tok).json(t, &one)
	if len(one) != 1 || one[0].RegionID != "101" || len(one[0].ActiveAlerts) != 1 || one[0].ActiveAlerts[0].RegionID != "10" {
		t.Fatalf("v3 one: %+v", one)
	}
	var st map[string]uint64
	do(t, ta.pub.URL, "/api/v3/alerts/status", tok).json(t, &st)
	v1 := st["lastActionIndex"]
	ta.fake.push("10", "AIR")
	waitFor(t, "end", func() bool { return ta.state.ActiveCount() == 0 })
	do(t, ta.pub.URL, "/api/v3/alerts/status", tok).json(t, &st)
	if st["lastActionIndex"] <= v1 {
		t.Fatalf("lastActionIndex must grow: %d → %d", v1, st["lastActionIndex"])
	}
	for _, p := range []string{"/api/v3/alerts/abc", "/api/v3/alerts/99999", "/api/v3/alerts/1/2"} {
		if r := do(t, ta.pub.URL, p, tok); r.code != 404 {
			t.Fatalf("%s: %d", p, r.code)
		}
	}
	var reg struct {
		States []v3Region `json:"states"`
	}
	do(t, ta.pub.URL, "/api/v3/regions", tok).json(t, &reg)
	if len(reg.States) != 2 {
		t.Fatalf("v3 regions: %d", len(reg.States))
	}
}

func TestRegionsETag(t *testing.T) {
	ta := newTestApp(t)
	tok, _ := ta.token(t)
	r := do(t, ta.pub.URL, "/api/v1/regions", tok)
	tag := r.hdr.Get("Etag")
	if r.code != 200 || tag == "" || !strings.Contains(r.body, `"Громада 101"`) {
		t.Fatalf("regions: %d %s", r.code, tag)
	}
	if r := do(t, ta.pub.URL, "/api/v1/regions", tok, "If-None-Match", tag); r.code != 304 || r.body != "" {
		t.Fatalf("304: %d %q", r.code, r.body)
	}
}

func TestPagesAndMethods(t *testing.T) {
	ta := newTestApp(t)
	tok, _ := ta.token(t)
	r := do(t, ta.pub.URL, "/", "")
	if r.code != 200 || !strings.Contains(r.hdr.Get("Content-Security-Policy"), indexScriptHash) || !strings.Contains(r.body, "Тривог немає.") {
		t.Fatalf("index: %d", r.code)
	}
	for _, w := range []string{"alertcast", "alertd", "token"} {
		if strings.Contains(strings.ToLower(r.body), w) {
			t.Fatalf("index reveals %q", w)
		}
	}
	if r := do(t, ta.pub.URL, "/s", ""); r.code != 200 || r.body != "ok ok ok\n" {
		t.Fatalf("/s: %q", r.body)
	}
	if r := do(t, ta.pub.URL, "/x", ""); r.code != 404 || !strings.Contains(r.body, `data-code="404"`) {
		t.Fatalf("404 page: %d", r.code)
	}
	req, _ := http.NewRequest("POST", ta.pub.URL+"/api/v1/status", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+tok)
	res, _ := http.DefaultClient.Do(req)
	res.Body.Close()
	if res.StatusCode != 405 || res.Header.Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST api: %d", res.StatusCode)
	}
	req, _ = http.NewRequest("POST", ta.pub.URL+"/", nil)
	res, _ = http.DefaultClient.Do(req)
	res.Body.Close()
	if res.StatusCode != 404 {
		t.Fatalf("POST page: %d", res.StatusCode)
	}
}

// ---------- потік ----------

func TestStreamSnapshotAndUpdates(t *testing.T) {
	ta := newTestApp(t)
	tok, _ := ta.token(t)
	st := openStream(t, ta.pub.URL, "/api/v1/stream?regions=101,1", tok)
	e := st.next(t, time.Second)
	var snap statusResp
	json.Unmarshal([]byte(e.data), &snap)
	if e.name != "snapshot" || snap.Regions["101"].State != "none" || len(snap.Regions) != 2 {
		t.Fatalf("snapshot: %+v", e)
	}
	ta.fake.push("10", "AIR", lv("Yellow", 0))
	got := map[string]string{}
	for i := 0; i < 2; i++ {
		e := st.next(t, 2*time.Second)
		var u struct {
			Region RegionStatus `json:"region"`
		}
		json.Unmarshal([]byte(e.data), &u)
		if e.name != "update" {
			t.Fatalf("event: %+v", e)
		}
		got[u.Region.ID] = u.Region.State + "/" + u.Region.Level
	}
	if got["101"] != "active/yellow" || got["1"] != "partial/yellow" {
		t.Fatalf("updates: %v", got)
	}
	// зміна в іншій області — нічого не надходить
	ta.fake.push("21", "AIR", lv("Red", 0))
	st.none(t, 300*time.Millisecond)
	// тривога в громаді іншого району: змінюється лише перелік «частково» в області; громади 101 це не стосується
	ta.fake.push("110", "AIR", lv("Yellow", 0))
	if e := st.next(t, 2*time.Second); e.name != "update" || !strings.Contains(e.data, `"id":"1"`) || !strings.Contains(e.data, `"partial":["10","110"]`) {
		t.Fatalf("partial list update: %+v", e)
	}
	st.none(t, 300*time.Millisecond)
	// той самий стан ще раз (повтор від alertd) — нічого
	ta.fake.push("110", "AIR", lv("Yellow", 0))
	st.none(t, 300*time.Millisecond)
	ta.fake.push("1", "AIR", lv("Red", 1)) // тривога на всю область: обидва регіони змінюються
	for i := 0; i < 2; i++ {
		if e := st.next(t, 2*time.Second); e.name != "update" || !strings.Contains(e.data, `"level":"red"`) {
			t.Fatalf("oblast alert: %+v", e)
		}
	}
}

func TestStreamLimitsAndKick(t *testing.T) {
	ta := newTestApp(t)
	tok, info := ta.token(t, func(s *TokenSpec) { s.Streams = ptr(2) })
	a := openStream(t, ta.pub.URL, "/api/v1/stream?regions=1", tok)
	b := openStream(t, ta.pub.URL, "/api/v1/stream?regions=2", tok)
	a.next(t, time.Second)
	b.next(t, time.Second)
	if c := openStream(t, ta.pub.URL, "/api/v1/stream?regions=1", tok); c.code != 429 {
		t.Fatalf("3rd stream: %d", c.code)
	}
	none, _ := ta.token(t, func(s *TokenSpec) { s.Streams = ptr(0) })
	if c := openStream(t, ta.pub.URL, "/api/v1/stream?regions=1", none); c.code != 429 {
		t.Fatalf("streams=0: %d", c.code)
	}
	// відкликання — потоки закриваються одразу з подією bye
	resp := ta.admin(adminReq{Op: "revoke", ID: info.ID})
	if !resp.OK || resp.Kicked != 2 {
		t.Fatalf("revoke: %+v", resp)
	}
	for _, s := range []*sseClient{a, b} {
		if e := s.next(t, time.Second); e.name != "bye" {
			t.Fatalf("bye: %+v", e)
		}
		select {
		case <-s.done:
		case <-time.After(time.Second):
			t.Fatal("stream not closed after revoke")
		}
	}
	if r := do(t, ta.pub.URL, "/api/v1/me", tok); r.code != 401 {
		t.Fatalf("revoked token works: %d", r.code)
	}
	waitFor(t, "hub empty", func() bool { n, _ := ta.hub.Count(); return n == 0 })
}

func TestStreamGlobalAndPerIPLimits(t *testing.T) {
	ta := newTestApp(t, func(c *Config, s *Source) { c.MaxStreams, c.MaxStreamsIP = 3, 2 })
	tok, _ := ta.token(t)
	open := func(ip string) int {
		ctx := t.Context()
		req, _ := http.NewRequestWithContext(ctx, "GET", ta.pub.URL+"/api/v1/stream?regions=1", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("X-Forwarded-For", "172.64.10.20")
		req.Header.Set("Cf-Connecting-Ip", ip)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != 200 {
			res.Body.Close()
		}
		return res.StatusCode
	}
	codes := []int{open("1.1.1.1"), open("1.1.1.1"), open("1.1.1.1"), open("2.2.2.2"), open("3.3.3.3")}
	if fmt.Sprint(codes) != "[200 200 503 200 503]" {
		t.Fatalf("limits: %v", codes)
	}
}

// Зміна налаштувань токена закриває його потоки (перепідключаться вже з новими правилами).
func TestEditKicksStreams(t *testing.T) {
	ta := newTestApp(t)
	tok, info := ta.token(t)
	s := openStream(t, ta.pub.URL, "/api/v1/stream?regions=1", tok)
	s.next(t, time.Second)
	if r := ta.admin(adminReq{Op: "edit", ID: info.ID, Spec: TokenSpec{RPM: ptr(10)}}); !r.OK || r.Kicked != 1 {
		t.Fatalf("edit: %+v", r)
	}
	if e := s.next(t, time.Second); e.name != "bye" {
		t.Fatalf("bye: %+v", e)
	}
	if r := do(t, ta.pub.URL, "/api/v1/me", tok); r.code != 200 || !strings.Contains(r.body, `"rpm":10`) {
		t.Fatalf("edited token: %d %s", r.code, r.body)
	}
	// rotate: старий секрет більше не працює, новий — так
	r := ta.admin(adminReq{Op: "rotate", ID: info.ID})
	if !r.OK || !looksLikeToken(r.Secret) {
		t.Fatalf("rotate: %+v", r)
	}
	if do(t, ta.pub.URL, "/api/v1/me", tok).code != 401 || do(t, ta.pub.URL, "/api/v1/me", r.Secret).code != 200 {
		t.Fatal("rotate semantics")
	}
}

// Протермінований під час потоку токен — потік закривається на найближчому ping.
func TestStreamExpiresMidway(t *testing.T) {
	ta := newTestApp(t)
	tok, info := ta.token(t, func(s *TokenSpec) { s.Expires = ptr(time.Now().Add(400 * time.Millisecond)) })
	s := openStream(t, ta.pub.URL, "/api/v1/stream?regions=1", tok)
	s.next(t, time.Second)
	_ = info
	select {
	case e := <-s.ev:
		if e.name != "bye" {
			t.Fatalf("event: %+v", e)
		}
	case <-time.After(16 * time.Second):
		t.Fatal("expired stream still open")
	}
}

// Багато потоків і швидкі зміни: кожен отримує фінальний стан, повільні не гальмують.
func TestManyStreamsConverge(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	ta := newTestApp(t, func(c *Config, s *Source) { c.MaxStreamsIP = 200 })
	tok, _ := ta.token(t, func(s *TokenSpec) { s.Streams = ptr(100) })
	const n = 100
	streams := make([]*sseClient, n)
	for i := range streams {
		streams[i] = openStream(t, ta.pub.URL, "/api/v1/stream?regions=100,1", tok)
		streams[i].next(t, 2*time.Second)
	}
	for i := 0; i < 50; i++ {
		ta.fake.push("10", "AIR", lv([]string{"Red", "Yellow"}[i%2], i))
	}
	ta.fake.push("10", "AIR", lv("Red", 99))
	waitFor(t, "all applied", func() bool { return ta.src.applied.Load() == 51 })
	want := statusKey(ta.state.Status("100"))
	var wg sync.WaitGroup
	errs := make(chan string, n)
	for _, s := range streams {
		wg.Add(1)
		go func(s *sseClient) {
			defer wg.Done()
			var last RegionStatus
			// чекати, доки потік не затихне на 500 мс, і порівняти останнє отримане з фактичним станом
			for {
				select {
				case e := <-s.ev:
					var u struct {
						Region RegionStatus `json:"region"`
					}
					if json.Unmarshal([]byte(e.data), &u) == nil && u.Region.ID == "100" {
						last = u.Region
					}
				case <-time.After(500 * time.Millisecond):
					if statusKey(last) != want {
						errs <- statusKey(last)
					}
					return
				}
			}
		}(s)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatalf("stream did not converge to the final state:\n got %s\nwant %s", e, want)
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

// Нова БД alertd, у якій номери подій уже перевищили старі: alertd не попросить resync
// (номер йому відомий), тож лише перевірка epoch не дає застосувати чужі події поверх старого стану.
func TestEpochCheckWhenNewSeqIsAhead(t *testing.T) {
	ta := newTestApp(t)
	ta.fake.push("10", "AIR", lv("Red", 0))
	waitFor(t, "old db alert", func() bool { return ta.state.Status("10").State == "active" })
	ta.fake.down.Store(true)
	ta.fake.newDB("e2")
	ta.fake.mu.Lock()
	ta.fake.active = map[string]stateItem{"21|AIR": {RegionID: "21", AlarmType: "AIR", Active: []Level{lv("Yellow", 0)}}}
	ta.fake.mu.Unlock()
	for i := 0; i < 3; i++ {
		ta.fake.push("22", "AIR", lv("Red", i))
	}
	ta.fake.down.Store(false)
	waitFor(t, "full resync to the new db", func() bool {
		return ta.state.Status("10").State == "none" && ta.state.Status("21").State == "active" &&
			ta.state.Status("22").State == "active"
	})
}

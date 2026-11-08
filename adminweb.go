package main

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/netip"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Адмінка: окремий вхід ADMIN_LISTEN (лише loopback; назовні — VPN-сайт панелі), один адмін,
// пароль + 2FA. Сторінки — статичні файли (без шаблонів і вбудованих скриптів, жорсткий CSP),
// дані — JSON-API /api/*. Зміни (POST/PATCH/DELETE) вимагають cookie сесії, заголовок X-CSRF
// і Origin цього ж сайту; тіло — лише application/json.

//go:embed www/admin
var adminFiles embed.FS

const adminCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
	"base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

const maxAdminLive = 8 // одночасних «наживо» (SSE) для адмінки

type adminCtxKey struct{}

type adminCtx struct {
	ip   netip.Addr
	id   string // id сесії (з cookie)
	sess *adminSess
}

func (a *App) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(adminFiles, "www/admin")
	static := func(name string) http.HandlerFunc {
		b, err := fs.ReadFile(sub, name)
		if err != nil {
			panic(err)
		}
		ct := mime.TypeByExtension(path.Ext(name))
		if strings.HasSuffix(name, ".html") {
			ct = "text/html; charset=utf-8"
		}
		return func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("Content-Type", ct)
			h.Set("Cache-Control", "no-cache")
			h.Set("Content-Length", strconv.Itoa(len(b)))
			if r.Method != http.MethodHead {
				w.Write(b)
			}
		}
	}
	shell := static("index.html")
	for _, p := range []string{"/{$}", "/login", "/tokens", "/tokens/new", "/tokens/{id}", "/test", "/journal"} {
		mux.HandleFunc("GET "+p, shell)
	}
	mux.HandleFunc("GET /admin.js", static("admin.js"))
	mux.HandleFunc("GET /admin.css", static("admin.css"))

	open := func(f func(http.ResponseWriter, *http.Request, *adminCtx)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) { f(w, r, r.Context().Value(adminCtxKey{}).(*adminCtx)) }
	}
	authed := func(f func(http.ResponseWriter, *http.Request, *adminCtx)) http.HandlerFunc {
		return open(func(w http.ResponseWriter, r *http.Request, c *adminCtx) {
			if c.sess == nil {
				apiError(w, r, http.StatusUnauthorized, "unauthorized")
				return
			}
			f(w, r, c)
		})
	}
	mux.HandleFunc("GET /api/me", open(a.admMe))
	mux.HandleFunc("POST /api/login", open(a.admLogin))
	mux.HandleFunc("POST /api/logout", open(a.admLogout))
	mux.HandleFunc("GET /api/overview", authed(func(w http.ResponseWriter, r *http.Request, c *adminCtx) {
		writeJSON(w, r, 200, a.admOverview(r.Context()))
	}))
	mux.HandleFunc("GET /api/live", authed(a.admLive))
	mux.HandleFunc("GET /api/metrics", authed(func(w http.ResponseWriter, r *http.Request, c *adminCtx) {
		writeJSON(w, r, 200, map[string]any{"minutes": a.metrics.History(), "now": time.Now().Unix()})
	}))
	mux.HandleFunc("GET /api/journal", authed(func(w http.ResponseWriter, r *http.Request, c *adminCtx) {
		n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		writeJSON(w, r, 200, a.journal.Recent(min(max(n, 1), journalMem), r.URL.Query().Get("kind")))
	}))
	mux.HandleFunc("GET /api/regions", authed(func(w http.ResponseWriter, r *http.Request, c *adminCtx) {
		writeJSON(w, r, 200, a.state.Tree().All())
	}))
	mux.HandleFunc("GET /api/tokens", authed(a.admTokens))
	mux.HandleFunc("POST /api/tokens", authed(a.admTokenAdd))
	mux.HandleFunc("GET /api/tokens/{id}", authed(a.admTokenGet))
	mux.HandleFunc("PATCH /api/tokens/{id}", authed(a.admTokenEdit))
	mux.HandleFunc("POST /api/tokens/{id}/rotate", authed(a.admTokenEdit))
	mux.HandleFunc("POST /api/tokens/{id}/kick", authed(func(w http.ResponseWriter, r *http.Request, c *adminCtx) {
		id := r.PathValue("id")
		if _, ok := a.tokens.Get(id); !ok {
			apiError(w, r, 404, "not found")
			return
		}
		n := a.hub.Kick(id)
		a.journal.Add("token", c.ip.String(), "Закрито потоки токена %s (%d)", id, n)
		writeJSON(w, r, 200, map[string]any{"ok": true, "kicked": n})
	}))
	mux.HandleFunc("DELETE /api/tokens/{id}", authed(func(w http.ResponseWriter, r *http.Request, c *adminCtx) {
		a.admReply(w, r, a.admin(adminReq{Op: "revoke", ID: r.PathValue("id"), Actor: c.ip.String()}), nil)
	}))
	mux.HandleFunc("GET /api/bans", authed(func(w http.ResponseWriter, r *http.Request, c *adminCtx) {
		writeJSON(w, r, 200, a.guard.Bans(time.Now()))
	}))
	mux.HandleFunc("POST /api/unban", authed(func(w http.ResponseWriter, r *http.Request, c *adminCtx) {
		var req struct{ IP string }
		if !readJSON(w, r, &req) {
			return
		}
		if !a.guard.Unban(req.IP) {
			apiError(w, r, 404, "не заблоковано")
			return
		}
		a.journal.Add("ban", c.ip.String(), "Знято блокування з %s", req.IP)
		writeJSON(w, r, 200, map[string]any{"ok": true})
	}))
	mux.HandleFunc("GET /api/test", authed(a.admTest))
	mux.HandleFunc("POST /api/test", authed(func(w http.ResponseWriter, r *http.Request, c *adminCtx) {
		var req struct{ Region, Type, Level string }
		if !readJSON(w, r, &req) {
			return
		}
		res := a.admin(adminReq{Op: "test-set", Region: req.Region, Type: req.Type, Level: req.Level, Actor: c.ip.String()})
		if !res.OK {
			apiError(w, r, 400, res.Error)
			return
		}
		a.admTest(w, r, c)
	}))
	mux.HandleFunc("DELETE /api/test", authed(func(w http.ResponseWriter, r *http.Request, c *adminCtx) {
		a.admin(adminReq{Op: "test-clear", Actor: c.ip.String()})
		a.admTest(w, r, c)
	}))

	return recoverer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", adminCSP)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Strict-Transport-Security", "max-age=31536000") // адмінка — лише через HTTPS (Caddy)
		ip := clientIP(r, a.cfg.AdminIPSource)
		if ok, retry := a.guard.allow(ip, time.Now()); !ok {
			retryAfter(w, retry)
			apiError(w, r, http.StatusTooManyRequests, "too many requests")
			return
		}
		c := &adminCtx{ip: ip}
		if ck, err := r.Cookie(adminCookie); err == nil {
			// фонове оновлення «наживо» не продовжує сесію: простій рахується від дій людини
			touch := r.URL.Path != "/api/live" && r.Header.Get("X-Background") == ""
			if s := a.admAuth.Session(ck.Value, touch); s != nil {
				c.id, c.sess = ck.Value, s
			}
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			// захист від CSRF: свій Origin, JSON і (для входу вже в сесії) X-CSRF
			if !sameOriginStrict(r) || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				apiError(w, r, http.StatusForbidden, "forbidden")
				return
			}
			if r.URL.Path != "/api/login" && (c.sess == nil || !constEq(r.Header.Get("X-CSRF"), c.sess.csrf)) {
				apiError(w, r, http.StatusForbidden, "csrf")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		}
		mux.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), adminCtxKey{}, c)))
	}))
}

func constEq(a, b string) bool {
	return a != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// sameOriginStrict — Origin обов'язковий і збігається з Host (усі сучасні браузери шлють
// Origin для fetch POST/PATCH/DELETE).
func sameOriginStrict(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" || o == "null" {
		return false
	}
	if sf := r.Header.Get("Sec-Fetch-Site"); sf != "" && sf != "same-origin" {
		return false
	}
	return sameOrigin(r)
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		apiError(w, r, http.StatusBadRequest, "bad json")
		return false
	}
	return true
}

func setAdminCookie(w http.ResponseWriter, v string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: adminCookie, Value: v, Path: "/", MaxAge: maxAge, HttpOnly: true,
		Secure: true, SameSite: http.SameSiteStrictMode})
}

func (a *App) admMe(w http.ResponseWriter, r *http.Request, c *adminCtx) {
	out := map[string]any{"configured": a.admAuth.Configured(), "authed": c.sess != nil}
	if c.sess != nil { // до входу — нічого зайвого (версія, адреса сервера)
		out["csrf"], out["ip"], out["version"], out["publicURL"] = c.sess.csrf, c.ip.String(), version, a.cfg.PublicURL
	}
	writeJSON(w, r, 200, out)
}

func (a *App) admLogin(w http.ResponseWriter, r *http.Request, c *adminCtx) {
	var req struct{ Password, Code string }
	if !readJSON(w, r, &req) {
		return
	}
	id, csrf, ban, err := a.admAuth.Login(c.ip, req.Password, req.Code)
	if ban != "" {
		a.journal.Add("login", c.ip.String(), "%s", ban)
		logf("admin: %s blocked: %s", c.ip, ban)
	}
	if err != nil {
		code := http.StatusUnauthorized
		switch {
		case errors.Is(err, errLoginBlocked):
			code = http.StatusTooManyRequests
		case errors.Is(err, errNotSetup):
			code = http.StatusServiceUnavailable
		case !errors.Is(err, errLoginBad):
			code = http.StatusInternalServerError
		}
		if code == http.StatusUnauthorized {
			a.journal.Add("login", c.ip.String(), "Невдала спроба входу в адмінку")
			logf("admin: failed login from %s", c.ip)
		}
		_, retry := a.admAuth.blocked(c.ip)
		writeJSON(w, r, code, map[string]any{"ok": false, "error": err.Error(), "retry": int(retry.Seconds() + 0.999)})
		return
	}
	setAdminCookie(w, id, int(adminAbsolute.Seconds()))
	a.journal.Add("login", c.ip.String(), "Вхід в адмінку")
	logf("admin: login from %s", c.ip)
	writeJSON(w, r, 200, map[string]any{"ok": true, "csrf": csrf})
}

func (a *App) admLogout(w http.ResponseWriter, r *http.Request, c *adminCtx) {
	if c.id != "" {
		a.admAuth.Logout(c.id)
		a.journal.Add("login", c.ip.String(), "Вихід з адмінки")
	}
	setAdminCookie(w, "", -1)
	writeJSON(w, r, 200, map[string]any{"ok": true})
}

// ---------- огляд ----------

type alertdStatsCache struct {
	mu   sync.Mutex
	at   time.Time
	data map[string]any
	err  string
}

func (a *App) alertdStats(ctx context.Context) (map[string]any, string) {
	c := &a.adStats
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.at) < 10*time.Second {
		return c.data, c.err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var m map[string]any
	if err := a.src.get(ctx, "/stats", &m); err != nil {
		c.data, c.err = nil, err.Error()
	} else {
		c.data, c.err = m, ""
	}
	c.at = time.Now()
	return c.data, c.err
}

func (a *App) admOverview(ctx context.Context) map[string]any {
	now := time.Now()
	total, byToken := a.hub.Count()
	stale, verified := a.src.Fresh(now)
	le, _ := a.src.lastErr.Load().(string)
	sum, last := a.metrics.Totals()
	ad, adErr := a.alertdStats(ctx)
	wd := watchdogOK.Load()
	return map[string]any{
		"now": now.Unix(), "version": version, "started": a.start.Unix(),
		"source": map[string]any{"connected": a.src.connected.Load(), "stale": stale, "verifiedAt": verified.Unix(),
			"reconnects": a.src.reconnects.Load(), "resyncs": a.src.resyncs.Load(), "lastError": le},
		"streams":      map[string]any{"total": total, "max": a.hub.MaxTotal, "tokens": len(byToken)},
		"activeAlerts": a.state.ActiveCount(),
		"tokens":       len(a.tokens.List()),
		"sessions":     a.sessions.Len(),
		"bans":         len(a.guard.Bans(now)),
		"requests24":   map[string]int64{"ok": sum.OK, "unauth": sum.Unauth, "forbid": sum.Forbid, "limited": sum.Limited, "events": sum.Events},
		"lastMinute":   last,
		"watchdog":     map[string]any{"enabled": watchdogInterval() > 0, "lastOK": wd},
		"alertd":       ad, "alertdError": adErr,
		"test": len(a.state.TestAlerts()),
	}
}

var adminLive atomic.Int32

// admLive — огляд кожні 2 с (SSE). Не продовжує сесію; закривається, щойно сесія скінчилась.
func (a *App) admLive(w http.ResponseWriter, r *http.Request, c *adminCtx) {
	if adminLive.Add(1) > maxAdminLive {
		adminLive.Add(-1)
		apiError(w, r, http.StatusTooManyRequests, "too many live views")
		return
	}
	defer adminLive.Add(-1)
	rc := http.NewResponseController(w)
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(200)
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	maxLife := time.NewTimer(30 * time.Minute) // браузер перепідключиться сам
	defer maxLife.Stop()
	send := func() bool {
		b, _ := json.Marshal(a.admOverview(r.Context()))
		_ = rc.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := fmt.Fprintf(w, "event: overview\ndata: %s\n\n", b); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	if !send() {
		return
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case <-maxLife.C:
			return
		case <-t.C:
			if a.admAuth.Session(c.id, false) == nil {
				fmt.Fprint(w, "event: logout\ndata: {}\n\n")
				rc.Flush()
				return
			}
			if !send() {
				return
			}
		}
	}
}

// ---------- токени ----------

type admTokenRow struct {
	TokenInfo
	Open   int         `json:"open"`
	Day    TokenMinute `json:"day"`
	Status string      `json:"status"` // active | expired
}

func (a *App) tokenRow(i TokenInfo, open map[string]int, sums map[string]TokenMinute, now time.Time) admTokenRow {
	st := "active"
	if !i.Expires.IsZero() && !now.Before(i.Expires) {
		st = "expired"
	}
	return admTokenRow{TokenInfo: i, Open: open[i.ID], Day: sums[i.ID], Status: st}
}

func (a *App) admTokens(w http.ResponseWriter, r *http.Request, c *adminCtx) {
	_, open := a.hub.Count()
	sums := a.metrics.TokenSums()
	now := time.Now()
	list := a.tokens.List()
	out := make([]admTokenRow, 0, len(list))
	for _, i := range list {
		out = append(out, a.tokenRow(i, open, sums, now))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	writeJSON(w, r, 200, out)
}

func (a *App) admTokenGet(w http.ResponseWriter, r *http.Request, c *adminCtx) {
	id := r.PathValue("id")
	i, ok := a.tokens.Get(id)
	if !ok {
		apiError(w, r, 404, "not found")
		return
	}
	_, open := a.hub.Count()
	streams := a.hub.List(id)
	if streams == nil {
		streams = []StreamInfo{}
	}
	writeJSON(w, r, 200, map[string]any{"token": a.tokenRow(i, open, a.metrics.TokenSums(), time.Now()),
		"streams": streams, "history": a.metrics.TokenHistory(id), "sessions": a.sessions.CountToken(id)})
}

// admSpec — специфікація з форми: термін як рядок ("", "7d", "2027-06-01", RFC3339).
type admSpec struct {
	Name       *string   `json:"name"`
	Expires    *string   `json:"expires"`
	RPM        *int      `json:"rpm"`
	Streams    *int      `json:"streams"`
	Regions    *[]string `json:"regions"`
	Nets       *[]string `json:"nets"`
	AllowQuery *bool     `json:"allowQuery"`
}

func (s admSpec) spec() (TokenSpec, error) {
	sp := TokenSpec{Name: s.Name, RPM: s.RPM, Streams: s.Streams, Regions: s.Regions, Nets: s.Nets, AllowQuery: s.AllowQuery}
	if s.Expires != nil {
		t, err := parseExpires(*s.Expires, time.Now())
		if err != nil {
			return sp, errors.New("термін: дата, 7d/30d або порожньо")
		}
		sp.Expires = &t
	}
	return sp, nil
}

// admReply — відповідь на операцію з токеном; для нового секрету — ще QR (адреса + токен).
func (a *App) admReply(w http.ResponseWriter, r *http.Request, res adminResp, extra map[string]any) {
	if !res.OK {
		code := 400
		if strings.Contains(res.Error, "немає") {
			code = 404
		}
		apiError(w, r, code, res.Error)
		return
	}
	out := map[string]any{"ok": true}
	if res.Token != nil {
		out["token"] = res.Token
	}
	if res.Secret != "" {
		out["secret"] = res.Secret
		out["qr"] = tokenQR(a.cfg.PublicURL, res.Secret)
	}
	if res.Kicked > 0 {
		out["kicked"] = res.Kicked
	}
	for k, v := range extra {
		out[k] = v
	}
	writeJSON(w, r, 200, out)
}

// tokenQR — SVG з JSON {"url":…, "token":…}; без адреси сервера — лише токен.
func tokenQR(publicURL, secret string) string {
	data := secret
	if publicURL != "" {
		b, _ := json.Marshal(map[string]string{"url": publicURL, "token": secret})
		data = string(b)
	}
	q, err := NewQR([]byte(data))
	if err != nil {
		return ""
	}
	return q.SVG()
}

func (a *App) admTokenAdd(w http.ResponseWriter, r *http.Request, c *adminCtx) {
	var s admSpec
	if !readJSON(w, r, &s) {
		return
	}
	sp, err := s.spec()
	if err != nil {
		apiError(w, r, 400, err.Error())
		return
	}
	a.admReply(w, r, a.admin(adminReq{Op: "add", Spec: sp, Actor: c.ip.String()}), nil)
}

func (a *App) admTokenEdit(w http.ResponseWriter, r *http.Request, c *adminCtx) {
	rotate := strings.HasSuffix(r.URL.Path, "/rotate")
	var s admSpec
	if !rotate && !readJSON(w, r, &s) {
		return
	}
	if rotate {
		_, _ = io.Copy(io.Discard, r.Body)
	}
	sp, err := s.spec()
	if err != nil {
		apiError(w, r, 400, err.Error())
		return
	}
	op := "edit"
	if rotate {
		op = "rotate"
	}
	a.admReply(w, r, a.admin(adminReq{Op: op, ID: r.PathValue("id"), Spec: sp, Actor: c.ip.String()}), nil)
}

// ---------- тестова область ----------

func (a *App) admTest(w http.ResponseWriter, r *http.Request, c *adminCtx) {
	tree := a.state.Tree()
	regions := []RegionStatus{}
	for _, rg := range testRegions {
		if _, ok := tree.Get(rg.ID); ok {
			regions = append(regions, a.state.Status(rg.ID))
		}
	}
	// хто бачить тестову область: токени, яким її дозволено явно
	_, open := a.hub.Count()
	type viewer struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Open int    `json:"open"`
	}
	viewers := []viewer{}
	for _, i := range a.tokens.List() {
		for _, rg := range i.Regions {
			if isTestRegion(rg) {
				viewers = append(viewers, viewer{i.ID, i.Name, open[i.ID]})
				break
			}
		}
	}
	alerts := a.state.TestAlerts()
	if alerts == nil {
		alerts = []TestAlert{}
	}
	resetAt := int64(0) // найближче автоскидання (кожна тривога — через testTTL після своєї зміни)
	for _, t := range alerts {
		if at := t.Changed.Add(testTTL).Unix(); resetAt == 0 || at < resetAt {
			resetAt = at
		}
	}
	writeJSON(w, r, 200, map[string]any{"enabled": len(regions) > 0, "regions": regions, "alerts": alerts,
		"viewers": viewers, "resetAt": resetAt, "types": testTypesAllowed})
}

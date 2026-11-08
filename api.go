package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// App — усе, що обслуговує HTTP: стан, джерело, токени, потоки, ліміти.
type App struct {
	cfg      Config
	state    *State
	src      *Source
	tokens   *Tokens
	hub      *Hub
	guard    *ipGuard
	sessions *Sessions
	metrics  *Metrics
	journal  *Journal
	admAuth  *AdminAuth
	adStats  alertdStatsCache
	index    indexCache
	start    time.Time

	reqTotal, reqDenied, reqLimited, reqErrors atomic.Int64

	regionsMu    sync.Mutex
	regionsTree  *Tree
	regionsV1    []byte
	regionsV3    []byte
	regionsV1Tag string
	regionsV3Tag string
}

// IP-джерело для входу: звідки брати справжню адресу клієнта.
const (
	ipRemote = "remote" // адреса з'єднання (без проксі)
	ipCF     = "cf"     // CF-Connecting-IP, лише якщо з'єднання від локального проксі
	ipXFF    = "xff"    // останній запис X-Forwarded-For, лише якщо з'єднання від локального проксі
)

func remoteAddr(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, _ := netip.ParseAddr(host)
	return a.Unmap()
}

// Мережі Cloudflare (https://www.cloudflare.com/ips/); замінюються змінною CF_RANGES.
const defaultCFRanges = "173.245.48.0/20,103.21.244.0/22,103.22.200.0/22,103.31.4.0/22,141.101.64.0/18," +
	"108.162.192.0/18,190.93.240.0/20,188.114.96.0/20,197.234.240.0/22,198.41.128.0/17,162.158.0.0/15," +
	"104.16.0.0/13,104.24.0.0/14,172.64.0.0/13,131.0.72.0/22," +
	"2400:cb00::/32,2606:4700::/32,2803:f800::/32,2405:b500::/32,2405:8100::/32,2a06:98c0::/29,2c0f:f248::/32"

var cfRanges = mustRanges(defaultCFRanges)

func parseRanges(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, p := range splitList(s) {
		pr, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, fmt.Errorf("CF_RANGES: %q", p)
		}
		out = append(out, pr.Masked())
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("CF_RANGES: порожньо")
	}
	return out, nil
}

func mustRanges(s string) []netip.Prefix {
	p, err := parseRanges(s)
	if err != nil {
		panic(err)
	}
	return p
}

func inRanges(a netip.Addr, rs []netip.Prefix) bool {
	for _, p := range rs {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// proxyPeer — адреса, з якої з'єднався з proxy (останній запис X-Forwarded-For: його ставить
// сам proxy, а не клієнт).
func proxyPeer(r *http.Request) (netip.Addr, bool) {
	vals := r.Header.Values("X-Forwarded-For")
	if len(vals) == 0 {
		return netip.Addr{}, false
	}
	parts := strings.Split(vals[len(vals)-1], ",")
	a, err := netip.ParseAddr(strings.TrimSpace(parts[len(parts)-1]))
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// clientIP — адреса клієнта. Заголовкам довіряємо лише тоді, коли з'єднання прийшло від
// локального reverse proxy. У режимі cf CF-Connecting-IP береться, лише якщо з proxy
// з'єднався саме вузол Cloudflare: публічний сайт може бути доступний і з VPN, і тоді клієнт
// підставив би будь-який CF-Connecting-IP — у такому разі береться його справжня адреса.
func clientIP(r *http.Request, source string) netip.Addr {
	ra := remoteAddr(r)
	if !ra.IsLoopback() || source == ipRemote {
		return ra
	}
	peer, ok := proxyPeer(r)
	if !ok {
		return ra
	}
	if source == ipCF && inRanges(peer, cfRanges) {
		if a, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("Cf-Connecting-Ip"))); err == nil {
			return a.Unmap()
		}
	}
	return peer
}

// ---------- відповіді ----------

func apiHeaders(h http.Header) {
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Robots-Tag", "noindex, nofollow")
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
}

func writeJSON(w http.ResponseWriter, r *http.Request, code int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		code, b = 500, []byte(`{"ok":false,"error":"internal"}`)
	}
	b = append(b, '\n')
	apiHeaders(w.Header())
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(code)
	if r.Method != http.MethodHead {
		w.Write(b)
	}
}

func apiError(w http.ResponseWriter, r *http.Request, code int, msg string) {
	writeJSON(w, r, code, struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}{false, msg})
}

// ---------- маршрутизація ----------

// Handler — один вхід (публічний або VPN) зі своїм правилом довіри до адреси клієнта.
// allowQuery=false — токен у адресі (?token=) не приймається взагалі (VPN-вхід: його журнал
// пише адреси повністю).
func (a *App) Handler(ipSource string, allowQuery bool) http.Handler {
	return recoverer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		isAPI := strings.HasPrefix(p, "/api/")
		sessionPath := p == "/api/v1/session" && (r.Method == http.MethodPost || r.Method == http.MethodDelete)
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !sessionPath {
			if isAPI {
				w.Header().Set("Allow", "GET, HEAD")
				apiError(w, r, http.StatusMethodNotAllowed, "method not allowed")
			} else {
				errorPage(w, r, http.StatusNotFound)
			}
			return
		}
		if !isAPI {
			switch p {
			case "/":
				a.serveIndex(w, r)
			case "/s":
				a.serveStatus(w, r)
			case "/docs/":
				http.Redirect(w, r, "/docs", http.StatusMovedPermanently)
			default:
				if !serveDocs(w, r) {
					errorPage(w, r, http.StatusNotFound)
				}
			}
			return
		}
		a.serveAPI(w, r, ipSource, allowQuery)
	}))
}

func recoverer(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				logf("panic in %s %s: %v", r.Method, clean(r.URL.Path, 80), v)
				if strings.HasPrefix(r.URL.Path, "/api/") {
					apiError(w, r, 500, "internal")
				} else {
					errorPage(w, r, 500)
				}
			}
		}()
		h.ServeHTTP(w, r)
	})
}

// rawToken — токен із запиту: Authorization (Bearer або як в ukrainealarm — без префікса),
// X-API-Key або ?token= (лише для токенів із дозволом).
func rawToken(r *http.Request) (string, bool) {
	if v := strings.TrimSpace(r.Header.Get("Authorization")); v != "" {
		if len(v) > 7 && strings.EqualFold(v[:7], "bearer ") {
			v = strings.TrimSpace(v[7:])
		}
		return v, false
	}
	if v := strings.TrimSpace(r.Header.Get("X-Api-Key")); v != "" {
		return v, false
	}
	if q := r.URL.Query(); q.Has("token") {
		return q.Get("token"), true
	}
	return "", false
}

// codeRec — повідомляє код відповіді в момент заголовків (потік рахується, коли відкрився,
// а не коли закрився); Unwrap — щоб працював ResponseController.
type codeRec struct {
	http.ResponseWriter
	code   int
	onCode func(int)
}

func (c *codeRec) WriteHeader(code int) {
	if c.code == 0 {
		c.code = code
		if c.onCode != nil {
			c.onCode(code)
		}
	}
	c.ResponseWriter.WriteHeader(code)
}

func (c *codeRec) Write(b []byte) (int, error) {
	if c.code == 0 {
		c.WriteHeader(200)
	}
	return c.ResponseWriter.Write(b)
}

func (c *codeRec) Unwrap() http.ResponseWriter { return c.ResponseWriter }

func (a *App) serveAPI(w0 http.ResponseWriter, r *http.Request, ipSource string, allowQuery bool) {
	now := time.Now()
	a.reqTotal.Add(1)
	ip := clientIP(r, ipSource)
	var tkID string
	w := &codeRec{ResponseWriter: w0, onCode: func(code int) {
		if a.metrics != nil {
			a.metrics.Request(tkID, code)
		}
	}}
	if ok, retry := a.guard.allow(ip, now); !ok {
		a.reqLimited.Add(1)
		retryAfter(w, retry)
		apiError(w, r, http.StatusTooManyRequests, "too many requests")
		return
	}
	if r.URL.Path == "/api/v1/session" && r.Method != http.MethodGet && r.Method != http.MethodHead {
		a.handleSession(w, r, ip)
		return
	}
	raw, viaQuery := rawToken(r)
	if viaQuery && !allowQuery {
		raw = "" // на цьому вході токен у адресі не приймається — як відсутній
	}
	var tk *token
	var err error
	if c, cerr := r.Cookie(sessionCookie); raw == "" && cerr == nil {
		// сесія браузера: той самий токен, ті самі обмеження
		err = errAuth
		if st := a.sessions.Get(c.Value); st != nil {
			tk, err = a.tokens.admit(st, ip, false)
		}
	} else {
		tk, err = a.tokens.Check(raw, ip, viaQuery)
	}
	if err != nil {
		var de deniedErr
		if errors.As(err, &de) {
			tkID = de.id
		}
		a.reqDenied.Add(1)
		if a.guard.fail(ip, now) {
			logf("auth: %s blocked for %s after repeated failures", ip, a.guard.banFor)
			a.journal.Add("ban", ip.String(), "Адресу заблоковано на %s після повторних невдалих спроб", humanDur(a.guard.banFor))
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="alertcast"`)
		apiError(w, r, http.StatusUnauthorized, "unauthorized")
		return
	}
	tkID = tk.ID
	if ok, retry := tk.bucket.take(now); !ok {
		a.reqLimited.Add(1)
		retryAfter(w, retry)
		apiError(w, r, http.StatusTooManyRequests, "rate limit")
		return
	}
	p := r.URL.Path
	switch {
	case p == "/api/v1/status":
		a.v1Status(w, r, tk)
	case p == "/api/v1/stream":
		a.v1Stream(w, r, tk, ip)
	case p == "/api/v1/regions":
		a.serveRegions(w, r, false)
	case p == "/api/v1/me":
		a.v1Me(w, r, tk, ip)
	case p == "/api/v3/alerts":
		a.v3Alerts(w, r, tk)
	case p == "/api/v3/alerts/status":
		writeJSON(w, r, 200, map[string]any{"lastActionIndex": a.state.Version()})
	case strings.HasPrefix(p, "/api/v3/alerts/"):
		a.v3AlertsOne(w, r, tk, strings.TrimPrefix(p, "/api/v3/alerts/"))
	case p == "/api/v3/regions":
		a.serveRegions(w, r, true)
	default:
		apiError(w, r, http.StatusNotFound, "not found")
	}
}

func retryAfter(w http.ResponseWriter, d time.Duration) {
	s := int(d.Seconds() + 0.999)
	if s < 1 {
		s = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(s))
}

// regionsParam — ?regions=1,2,3: перевірені й дозволені ID. Без параметра — регіони токена.
func (a *App) regionsParam(w http.ResponseWriter, r *http.Request, tk *token) ([]string, bool) {
	q := r.URL.Query()
	var ids []string
	if v := q.Get("regions"); v != "" {
		if len(v) > 4096 {
			apiError(w, r, http.StatusBadRequest, "regions: too long")
			return nil, false
		}
		seen := map[string]bool{}
		for _, s := range strings.Split(v, ",") {
			s = strings.TrimSpace(s)
			if s == "" || seen[s] {
				continue
			}
			seen[s] = true
			ids = append(ids, s)
		}
	} else {
		ids = append(ids, tk.Regions...)
	}
	if len(ids) == 0 {
		apiError(w, r, http.StatusBadRequest, "regions: required (e.g. ?regions=4,32)")
		return nil, false
	}
	if len(ids) > a.cfg.MaxRegions {
		apiError(w, r, http.StatusBadRequest, fmt.Sprintf("regions: at most %d", a.cfg.MaxRegions))
		return nil, false
	}
	tree := a.state.Tree()
	for _, id := range ids {
		if !validID(id) {
			apiError(w, r, http.StatusBadRequest, "regions: ids are digits")
			return nil, false
		}
		if _, ok := tree.Get(id); !ok {
			if tree.Len() == 0 {
				apiError(w, r, http.StatusServiceUnavailable, "not ready")
			} else {
				apiError(w, r, http.StatusBadRequest, "unknown region "+id)
			}
			return nil, false
		}
		if !tk.Allowed(tree, id) {
			apiError(w, r, http.StatusForbidden, "region "+id+" not allowed for this token")
			return nil, false
		}
	}
	return ids, true
}

type statusResp struct {
	OK       bool                    `json:"ok"`
	Stale    bool                    `json:"stale"`
	Verified jtime                   `json:"verifiedAt"`
	Version  uint64                  `json:"version"`
	Regions  map[string]RegionStatus `json:"regions"`
}

func (a *App) snapshot(ids []string) statusResp {
	st := a.state
	stale, verified := a.src.Fresh(time.Now())
	out := statusResp{OK: true, Stale: stale, Verified: jtime{verified}, Regions: make(map[string]RegionStatus, len(ids))}
	st.mu.RLock()
	out.Version = st.version
	for _, id := range ids {
		out.Regions[id] = st.statusLocked(id)
	}
	st.mu.RUnlock()
	return out
}

func (a *App) v1Status(w http.ResponseWriter, r *http.Request, tk *token) {
	ids, ok := a.regionsParam(w, r, tk)
	if !ok {
		return
	}
	writeJSON(w, r, 200, a.snapshot(ids))
}

func (a *App) v1Me(w http.ResponseWriter, r *http.Request, tk *token, ip netip.Addr) {
	_, byToken := a.hub.Count()
	i := tk.info()
	writeJSON(w, r, 200, map[string]any{
		"ok": true, "id": i.ID, "name": i.Name, "expires": jtime{i.Expires}, "rpm": i.RPM, "streams": i.Streams,
		"streamsOpen": byToken[i.ID], "regions": i.Regions, "nets": i.Nets, "allowQuery": i.AllowQuery, "ip": ip.String(),
	})
}

// ---------- потік ----------

// v1Stream — SSE: спершу знімок запитаних регіонів (snapshot), далі лише зміни (update),
// зміна свіжості даних (meta), ping кожні 15 с. Після обриву клієнт перепідключається й
// знову отримує знімок — загубити зміну неможливо.
func (a *App) v1Stream(w http.ResponseWriter, r *http.Request, tk *token, ip netip.Addr) {
	ids, ok := a.regionsParam(w, r, tk)
	if !ok {
		return
	}
	sub := newSub(ids, tk.ID, ipKey(ip).String())
	sub.Listener = listenerName(r)
	switch a.hub.Add(sub, tk.Streams) {
	case "":
	case "token":
		apiError(w, r, http.StatusTooManyRequests, "too many streams for this token")
		return
	default:
		retryAfter(w, 30*time.Second)
		apiError(w, r, http.StatusServiceUnavailable, "too many streams")
		return
	}
	defer a.hub.Remove(sub)

	rc := http.NewResponseController(w)
	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	var buf bytes.Buffer
	flush := func() bool {
		_ = rc.SetWriteDeadline(time.Now().Add(15 * time.Second))
		if _, err := w.Write(buf.Bytes()); err != nil {
			return false
		}
		buf.Reset()
		return rc.Flush() == nil
	}
	event := func(name string, v any) {
		b, _ := json.Marshal(v)
		fmt.Fprintf(&buf, "event: %s\ndata: %s\n\n", name, b)
	}
	// випадкова затримка перепідключення — щоб після перезапуску клієнти не прийшли разом
	fmt.Fprintf(&buf, "retry: %d\n\n", 1000+rand.IntN(4000))
	snap := a.snapshot(ids)
	event("snapshot", snap)
	last := make(map[string]string, len(ids))
	for id, st := range snap.Regions {
		last[id] = statusKey(st)
	}
	lastStale := snap.Stale
	if !flush() {
		return
	}
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-sub.kick:
			event("bye", map[string]string{"reason": "token changed"})
			flush()
			return
		case <-ping.C:
			if !a.tokens.Current(tk) || tk.Expired(time.Now()) {
				event("bye", map[string]string{"reason": "token expired or revoked"})
				flush()
				return
			}
			// запасна перевірка свіжості: навіть якщо сигнал загубився, клієнт дізнається за ≤ 15 с
			if stale, verified := a.src.Fresh(time.Now()); stale != lastStale {
				lastStale = stale
				event("meta", metaEv{Stale: stale, Verified: jtime{verified}})
			}
			buf.WriteString(": ping\n\n")
			if !flush() {
				return
			}
		case <-sub.dirty:
			world := a.state
			stale, verified := a.src.Fresh(time.Now())
			if stale != lastStale {
				lastStale = stale
				event("meta", metaEv{Stale: stale, Verified: jtime{verified}})
			}
			world.mu.RLock()
			ver := world.version
			var changed []RegionStatus
			for _, id := range ids {
				st := world.statusLocked(id)
				if k := statusKey(st); k != last[id] {
					last[id] = k
					changed = append(changed, st)
				}
			}
			world.mu.RUnlock()
			for _, st := range changed {
				event("update", updateEv{Version: ver, Region: st})
			}
			if buf.Len() > 0 {
				if !flush() {
					return
				}
				if len(changed) > 0 {
					sub.Sent.Add(int64(len(changed)))
					if ai, ok := a.state.appliedInfo(ver); ok && a.metrics != nil {
						now := time.Now()
						a.metrics.Delivered(now.Sub(ai.at), now.Sub(ai.created), ai.webhook)
					}
				}
			}
		}
	}
}

type metaEv struct {
	Stale    bool  `json:"stale"`
	Verified jtime `json:"verifiedAt"`
}

type updateEv struct {
	Version uint64       `json:"version"`
	Region  RegionStatus `json:"region"`
}

// ---------- дерево регіонів (кеш + ETag) ----------

type regionV1 struct {
	Test   bool   `json:"test,omitempty"`
	ID     string `json:"id"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Parent string `json:"parent,omitempty"`
	State  string `json:"state,omitempty"`
}

func (a *App) regionsCache() (v1, v3 []byte, t1, t3 string) {
	tree := a.state.Tree()
	a.regionsMu.Lock()
	defer a.regionsMu.Unlock()
	if a.regionsTree != tree {
		list := make([]regionV1, 0, tree.Len())
		var walk func(ids []string, depth int)
		walk = func(ids []string, depth int) {
			for _, id := range ids {
				rg := tree.byID[id]
				list = append(list, regionV1{ID: id, Name: rg.Name, Type: rg.Type, Parent: rg.ParentID, State: rg.StateID, Test: isTestRegion(id)})
				if depth < maxDepth {
					walk(tree.children[id], depth+1)
				}
			}
		}
		walk(tree.roots, 0)
		a.regionsV1, _ = json.Marshal(map[string]any{"ok": true, "regions": list})
		a.regionsV3, _ = json.Marshal(map[string]any{"states": tree.V3Regions()})
		tag := func(b []byte) string { h := sha256.Sum256(b); return `"` + hex.EncodeToString(h[:12]) + `"` }
		a.regionsV1Tag, a.regionsV3Tag = tag(a.regionsV1), tag(a.regionsV3)
		a.regionsTree = tree
	}
	return a.regionsV1, a.regionsV3, a.regionsV1Tag, a.regionsV3Tag
}

func (a *App) serveRegions(w http.ResponseWriter, r *http.Request, v3 bool) {
	if a.state.Tree().Len() == 0 {
		apiError(w, r, http.StatusServiceUnavailable, "not ready")
		return
	}
	b1, b3, t1, t3 := a.regionsCache()
	body, tag := b1, t1
	if v3 {
		body, tag = b3, t3
	}
	apiHeaders(w.Header())
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ETag", tag)
	if inm := r.Header.Get("If-None-Match"); inm != "" && strings.Contains(inm, tag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)+1))
	w.WriteHeader(200)
	if r.Method != http.MethodHead {
		w.Write(body)
		w.Write([]byte{'\n'})
	}
}

// ---------- сумісність з ukrainealarm v3 ----------

func (a *App) markStale(w http.ResponseWriter) *State {
	if stale, _ := a.src.Fresh(time.Now()); stale {
		w.Header().Set("X-Data-Stale", "1")
	}
	return a.state
}

func (a *App) v3Alerts(w http.ResponseWriter, r *http.Request, tk *token) {
	recs := a.markStale(w).V3All()
	if len(tk.Regions) > 0 {
		tree := a.state.Tree()
		f := make([]v3Record, 0, len(recs))
		for _, rec := range recs {
			if tk.Allowed(tree, rec.RegionID) {
				f = append(f, rec)
			}
		}
		recs = f
	}
	writeJSON(w, r, 200, recs)
}

func (a *App) v3AlertsOne(w http.ResponseWriter, r *http.Request, tk *token, id string) {
	tree := a.state.Tree()
	if !validID(id) {
		apiError(w, r, http.StatusNotFound, "not found")
		return
	}
	if _, ok := tree.Get(id); !ok || isTestRegion(id) {
		apiError(w, r, http.StatusNotFound, "unknown region "+id)
		return
	}
	if !tk.Allowed(tree, id) {
		apiError(w, r, http.StatusForbidden, "region "+id+" not allowed for this token")
		return
	}
	writeJSON(w, r, 200, []v3Record{a.markStale(w).V3Record(id)})
}

// ---------- локальний API (лише loopback): здоров'я і статистика ----------

func (a *App) LocalHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		stale, verified := a.src.Fresh(time.Now())
		code := 200
		if stale {
			code = 503
		}
		writeJSON(w, r, code, map[string]any{"ok": !stale, "connected": a.src.connected.Load(), "verifiedAt": jtime{verified}})
	})
	// усі записи v3 без фільтра токена — для «alertcast verify» (лише loopback)
	mux.HandleFunc("GET /v3/alerts", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, r, 200, a.state.V3All())
	})
	mux.HandleFunc("GET /stats", func(w http.ResponseWriter, r *http.Request) {
		total, byToken := a.hub.Count()
		stale, verified := a.src.Fresh(time.Now())
		le, _ := a.src.lastErr.Load().(string)
		writeJSON(w, r, 200, map[string]any{
			"version": version, "uptime": time.Since(a.start).Round(time.Second).String(),
			"source": map[string]any{"connected": a.src.connected.Load(), "stale": stale, "verifiedAt": jtime{verified},
				"epoch": a.src.epochV.Load(), "applied": a.src.applied.Load(), "reconnects": a.src.reconnects.Load(),
				"resyncs": a.src.resyncs.Load(), "lastError": le},
			"state":    map[string]any{"version": a.state.Version(), "activeAlerts": a.state.ActiveCount(), "regions": a.state.Tree().Len()},
			"streams":  map[string]any{"total": total, "byToken": byToken, "max": a.hub.MaxTotal},
			"tokens":   len(a.tokens.List()),
			"requests": map[string]int64{"total": a.reqTotal.Load(), "unauthorized": a.reqDenied.Load(), "limited": a.reqLimited.Load()},
			"ipGuard":  map[string]any{"tracked": a.guard.size(), "bans": a.guard.bans.Load()},
			"sessions": a.sessions.Len(),
		})
	})
	return mux
}

type listenerKey struct{}

// listenerName — на якому вході відкрито потік (для адмінки): public | vpn.
func listenerName(r *http.Request) string {
	if v, ok := r.Context().Value(listenerKey{}).(string); ok {
		return v
	}
	return "public"
}

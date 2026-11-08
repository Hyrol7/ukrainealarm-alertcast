package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeAlertd — підставний alertd: /regions, /state, /health, /events (SSE з hello).
type fakeAlertd struct {
	mu       sync.Mutex
	regions  []Region
	epoch    string
	seq      int64
	active   map[string]stateItem // regionId|type
	backlog  []string             // події (сирі SSE-блоки) для after=…
	streams  map[chan string]struct{}
	lastSync atomic.Int64
	down     atomic.Bool // відповідати 503 на все
	silent   atomic.Bool // відкривати потік, але не слати нічого (навіть ping)
	conns    atomic.Int64
	hs       *httptest.Server
}

func newFakeAlertd(t testing.TB) *fakeAlertd {
	f := &fakeAlertd{regions: sampleRegions(), epoch: "e1", active: map[string]stateItem{}, streams: map[chan string]struct{}{}}
	f.lastSync.Store(time.Now().Unix())
	f.hs = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(func() { f.dropAll(); f.hs.Close() })
	return f
}

func (f *fakeAlertd) serve(w http.ResponseWriter, r *http.Request) {
	if f.down.Load() {
		http.Error(w, "down", 503)
		return
	}
	switch r.URL.Path {
	case "/regions":
		f.mu.Lock()
		b, _ := json.Marshal(f.regions)
		f.mu.Unlock()
		w.Write(b)
	case "/state":
		f.mu.Lock()
		items := make([]stateItem, 0, len(f.active))
		for _, it := range f.active {
			items = append(items, it)
		}
		b, _ := json.Marshal(map[string]any{"api": 1, "epoch": f.epoch, "seq": f.seq, "active": items})
		f.mu.Unlock()
		w.Write(b)
	case "/health":
		fmt.Fprintf(w, `{"ok":true,"lastSync":%d}`, f.lastSync.Load())
	case "/stats":
		now := time.Now().UTC().Format(time.RFC3339)
		fmt.Fprintf(w, `{"version":"1.0.0","uptime":"72h3m","webhooks":{"accepted":1284,"duplicates":3,"rejected":0,"badJSON":0},`+
			`"lastWebhook":%q,"lastSync":%q,"webhookMisses":0,"reconcileFixes":2,"apiPausedUntil":null,"db":{"dropped":0}}`, now, now)
	case "/events":
		f.conns.Add(1)
		fl := w.(http.Flusher)
		w.Header().Set("Content-Type", "text/event-stream")
		ch := make(chan string, 1024)
		f.mu.Lock()
		after := int64(0)
		fmt.Sscan(r.URL.Query().Get("after"), &after)
		fmt.Fprintf(w, "retry: 1000\n\nevent: hello\ndata: {\"api\":1,\"epoch\":%q,\"seq\":%d}\n\n", f.epoch, f.seq)
		if after > f.seq {
			fmt.Fprintf(w, "event: resync\ndata: {}\n\n")
		} else {
			for i := after; i < int64(len(f.backlog)); i++ {
				io.WriteString(w, f.backlog[i])
			}
		}
		f.streams[ch] = struct{}{}
		f.mu.Unlock()
		fl.Flush()
		defer func() { f.mu.Lock(); delete(f.streams, ch); f.mu.Unlock() }()
		tick := time.NewTicker(200 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case s, ok := <-ch:
				if !ok {
					return
				}
				io.WriteString(w, s)
				fl.Flush()
			case <-tick.C:
				if !f.silent.Load() {
					io.WriteString(w, ": ping\n\n")
					fl.Flush()
				}
			}
		}
	default:
		http.NotFound(w, r)
	}
}

// push — зміна в alertd: оновити стан і розіслати подію alert.
func (f *fakeAlertd) push(region, typ string, levels ...Level) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	change := "start"
	k := region + "|" + typ
	if _, ok := f.active[k]; ok {
		change = "update"
	}
	if len(levels) == 0 {
		change = "end"
		delete(f.active, k)
	} else {
		f.active[k] = stateItem{RegionID: region, AlarmType: typ, Since: jtime{t0}, Active: levels}
	}
	if levels == nil {
		levels = []Level{}
	}
	ev, _ := json.Marshal(map[string]any{"seq": f.seq, "regionId": region, "alarmType": typ, "change": change,
		"activeAlertLevels": levels, "sessionStartedAt": jtime{t0}})
	blk := fmt.Sprintf("id: %d\nevent: alert\ndata: %s\n\n", f.seq, ev)
	f.backlog = append(f.backlog, blk)
	for ch := range f.streams {
		select {
		case ch <- blk:
		default:
		}
	}
}

func (f *fakeAlertd) send(raw string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for ch := range f.streams {
		ch <- raw
	}
}

func (f *fakeAlertd) dropAll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for ch := range f.streams {
		close(ch)
		delete(f.streams, ch)
	}
}

// newDB — alertd створив нову БД: новий epoch і нумерація з нуля.
func (f *fakeAlertd) newDB(epoch string) {
	f.mu.Lock()
	f.epoch, f.seq, f.backlog = epoch, 0, nil
	f.mu.Unlock()
	f.dropAll()
}

// ---------- тестовий alertcast ----------

type testApp struct {
	*App
	fake   *fakeAlertd
	pub    *httptest.Server // публічний вхід (ip: cf)
	vpn    *httptest.Server // VPN-вхід (ip: xff)
	cancel context.CancelFunc
	dir    string
}

func testConfig() Config {
	return Config{PublicIPSource: ipCF, VPNIPSource: ipXFF, AdminIPSource: ipXFF, StaleAfter: 5 * time.Minute, MaxStreams: 200,
		MaxStreamsIP: 50, IPRPM: 100000, AuthFailLimit: 10, AuthFailWindow: 10 * time.Minute, AuthBan: 15 * time.Minute,
		MaxRegions: 64, DefaultRPM: 6000, DefaultStreams: 10}
}

func newTestApp(t testing.TB, mod ...func(*Config, *Source)) *testApp {
	t.Helper()
	fake := newFakeAlertd(t)
	cfg := testConfig()
	cfg.AlertdURL = fake.hs.URL
	dir := t.TempDir()
	tokens, err := OpenTokens(filepath.Join(dir, "ac.db"))
	if err != nil {
		t.Fatal(err)
	}
	state := NewState()
	hub := NewHub(state.StateOf, cfg.MaxStreams, cfg.MaxStreamsIP)
	src := NewSource(fake.hs.URL, state, hub, cfg.StaleAfter)
	src.idleTimeout, src.healthEvery = 2*time.Second, 100*time.Millisecond
	for _, m := range mod {
		m(&cfg, src)
	}
	hub.MaxTotal, hub.MaxPerIP = cfg.MaxStreams, cfg.MaxStreamsIP
	app := &App{cfg: cfg, state: state, src: src, tokens: tokens, hub: hub, start: time.Now(), sessions: NewSessions(),
		guard: newIPGuard(cfg.IPRPM, cfg.AuthFailLimit, cfg.AuthFailWindow, cfg.AuthBan)}
	if err := app.attachDB(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go src.Run(ctx)
	ta := &testApp{App: app, fake: fake, cancel: cancel, dir: dir}
	ta.pub = httptest.NewServer(named("public", app.Handler(cfg.PublicIPSource, true)))
	ta.vpn = httptest.NewServer(named("vpn", app.Handler(cfg.VPNIPSource, false)))
	t.Cleanup(func() {
		hub.Kick("")
		ta.pub.Close()
		ta.vpn.Close()
		cancel()
		app.metrics.Wait()
		tokens.Close()
	})
	waitFor(t, "initial state", func() bool { stale, _ := src.Fresh(time.Now()); return !stale })
	return ta
}

func waitFor(t testing.TB, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func ptr[T any](v T) *T { return &v }

// token — створити токен; mod змінює специфікацію.
func (ta *testApp) token(t testing.TB, mod ...func(*TokenSpec)) (string, TokenInfo) {
	t.Helper()
	sp := TokenSpec{Name: ptr("test")}
	for _, m := range mod {
		m(&sp)
	}
	i, raw, err := ta.tokens.Add(sp, ta.state.Tree(), ta.cfg.DefaultRPM, ta.cfg.DefaultStreams)
	if err != nil {
		t.Fatal(err)
	}
	return raw, i
}

type resp struct {
	code int
	hdr  http.Header
	body string
}

func (r resp) json(t testing.TB, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(r.body), v); err != nil {
		t.Fatalf("json: %v: %s", err, r.body)
	}
}

func do(t testing.TB, base, path, tok string, hdr ...string) resp {
	t.Helper()
	req, _ := http.NewRequest("GET", base+path, nil)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return resp{res.StatusCode, res.Header, string(b)}
}

// sseClient — читач потоку: події (name + data) у канал.
type sseEvent struct{ name, data string }

type sseClient struct {
	ev     chan sseEvent
	cancel context.CancelFunc
	done   chan struct{}
	code   int
}

func openStream(t testing.TB, base, path, tok string) *sseClient {
	t.Helper()
	return openStreamWith(t, base+path, func(req *http.Request) {
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
	})
}

func openStreamWith(t testing.TB, url string, prep func(*http.Request)) *sseClient {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	prep(req)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	c := &sseClient{ev: make(chan sseEvent, 64), cancel: cancel, done: make(chan struct{}), code: res.StatusCode}
	t.Cleanup(cancel)
	if res.StatusCode != 200 {
		res.Body.Close()
		close(c.done)
		return c
	}
	go func() {
		defer close(c.done)
		defer res.Body.Close()
		sc := bufio.NewScanner(res.Body)
		sc.Buffer(make([]byte, 4096), 1<<20)
		var name, data string
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == "":
				if name != "" {
					c.ev <- sseEvent{name, data}
				}
				name, data = "", ""
			case strings.HasPrefix(line, "event: "):
				name = line[7:]
			case strings.HasPrefix(line, "data: "):
				data = line[6:]
			}
		}
	}()
	return c
}

func (c *sseClient) next(t testing.TB, within time.Duration) sseEvent {
	t.Helper()
	select {
	case e := <-c.ev:
		return e
	case <-time.After(within):
		t.Fatalf("no SSE event within %s", within)
		return sseEvent{}
	}
}

// none — за час d не прийшло жодної події (крім дозволених імен).
func (c *sseClient) none(t testing.TB, d time.Duration) {
	t.Helper()
	select {
	case e := <-c.ev:
		t.Fatalf("unexpected event %s: %s", e.name, e.data)
	case <-time.After(d):
	}
}

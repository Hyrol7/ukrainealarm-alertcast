package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Випадкові шляхи, параметри й заголовки: без панік, лише очікувані коди, JSON для /api/.
func FuzzAPIRequest(f *testing.F) {
	for _, s := range []string{"/api/v1/status?regions=1,10", "/api/v3/alerts/101", "/api/v1/stream?regions=", "/",
		"/api/v1/status?regions=%00", "/api/v3/alerts/../../etc", "/api/v1/regions", "/s"} {
		f.Add(s, "Bearer ac_x", "1.2.3.4")
	}
	ta := newTestApp(f)
	tok, _ := ta.token(f)
	h := ta.App.Handler(ipCF, true)
	ok := map[int]bool{200: true, 304: true, 400: true, 401: true, 403: true, 404: true, 405: true, 429: true, 503: true}
	f.Fuzz(func(t *testing.T, target, auth, ip string) {
		if !strings.HasPrefix(target, "/") || strings.ContainsAny(target, " \r\n#") {
			return
		}
		u, err := url.ParseRequestURI(target)
		if err != nil || strings.HasPrefix(u.Path, "/api/v1/stream") {
			return // потоки тут не відкриваємо (вони довгі)
		}
		r := httptest.NewRequest("GET", target, nil)
		r.RemoteAddr = "127.0.0.1:1234"
		if strings.Contains(auth, "TOKEN") {
			auth = strings.ReplaceAll(auth, "TOKEN", tok)
		}
		if !strings.ContainsAny(auth, "\r\n\x00") {
			r.Header.Set("Authorization", auth)
		}
		r.Header.Set("X-Forwarded-For", "172.64.0.1")
		if !strings.ContainsAny(ip, "\r\n\x00") {
			r.Header.Set("Cf-Connecting-Ip", ip)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if !ok[w.Code] {
			t.Fatalf("%s: unexpected %d", target, w.Code)
		}
		if strings.HasPrefix(u.Path, "/api/") && w.Code != 304 && !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
			t.Fatalf("%s: api answered %s", target, w.Header().Get("Content-Type"))
		}
	})
}

// Випадковий «потік alertd»: парсер не панікує, не зависає, стан лишається узгодженим.
func FuzzAlertdStream(f *testing.F) {
	f.Add("event: hello\ndata: {\"api\":1,\"epoch\":\"e1\",\"seq\":0}\n\nid: 1\nevent: alert\ndata: {\"regionId\":\"10\",\"alarmType\":\"AIR\",\"change\":\"start\",\"activeAlertLevels\":[{\"alertLevel\":\"Red\"}]}\n\n")
	f.Add("event: hello\ndata: {\"api\":1,\"epoch\":\"e1\"}\n\nevent: alert\ndata: {\"regionId\":\"x\",\"alarmType\":\"\"}\n\n")
	f.Add("event: alert\ndata: {}\n\n")
	f.Add("event: hello\ndata: not json\n\n")
	f.Add(strings.Repeat("data: ", 1000))
	var cur atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, cur.Load().(string))
	}))
	defer srv.Close()
	f.Fuzz(func(t *testing.T, body string) {
		cur.Store(body)
		state := NewState()
		state.SetTree(BuildTree(sampleRegions()))
		src := NewSource(srv.URL, state, NewHub(state.StateOf, 10, 10), time.Minute)
		src.epoch = "e1"
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		done := make(chan struct{})
		go func() { src.stream(ctx); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("stream parser hung")
		}
		for _, r := range sampleRegions() {
			_ = state.Status(r.ID)
		}
		_ = state.V3All()
	})
}

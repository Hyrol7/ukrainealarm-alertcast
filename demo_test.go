package main

import (
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"testing"
	"time"
)

// DEMO_DIR=… go test -run TestDemoServer -timeout 0 — адмінка з даними для перегляду в браузері:
// адмінка на DEMO_DIR/addr, секрет 2FA у DEMO_DIR/secret, пароль pass-pass-pass.
func TestDemoServer(t *testing.T) {
	dir := os.Getenv("DEMO_DIR")
	if dir == "" {
		t.Skip("DEMO_DIR not set")
	}
	ta := newTestApp(t)
	ta.cfg.PublicURL = "https://alerts.example.com"
	sec, _ := newTOTPSecret()
	hsh, _ := hashPassword("pass-pass-pass")
	ta.admAuth.Set(hsh, sec)
	if os.Getenv("DEMO_EMPTY") == "" {
		seedDemo(t, ta, dir)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(dir+"/addr", []byte(ln.Addr().String()), 0o644)
	os.WriteFile(dir+"/secret", []byte(sec), 0o644)
	os.WriteFile(dir+"/public", []byte(ta.pub.URL), 0o644)
	http.Serve(ln, ta.AdminHandler())
}

func seedDemo(t *testing.T, ta *testApp, dir string) {
	for _, p := range []struct {
		r, ty string
		l     []Level
	}{{"2", "AIR", []Level{lv("Red", 0)}}, {"11", "AIR", []Level{lv("Yellow", 0)}}, {"121", "ARTILLERY", nil}} {
		ta.fake.push(p.r, p.ty, append(p.l, lv("", 0))...)
	}
	ta.token(t, func(s *TokenSpec) {
		s.Name = ptr("Лампа кухня")
		s.Regions = &[]string{"11", "990000"}
		s.RPM = ptr(30)
		s.Streams = ptr(1)
	})
	exp := time.Now().Add(-24 * time.Hour)
	ta.token(t, func(s *TokenSpec) {
		s.Name = ptr("Старий планшет")
		s.Regions = &[]string{"1"}
		s.Expires = &exp
	})
	sec2, tk := ta.token(t, func(s *TokenSpec) { s.Name = ptr("Telegram-бот"); s.Nets = &[]string{"127.0.0.1"} })
	os.WriteFile(dir+"/token", []byte(sec2), 0o644)
	for i := 0; i < 5; i++ {
		do(t, ta.pub.URL, "/api/v1/status?regions=1", sec2)
	}
	openStream(t, ta.pub.URL, "/api/v1/stream?regions=1,2", sec2)
	ta.admin(adminReq{Op: "test-set", Region: "990100", Level: "red"})
	for i := 0; i < ta.cfg.AuthFailLimit; i++ {
		do(t, ta.pub.URL, "/api/v1/me", "ac_bad", "X-Forwarded-For", "198.51.100.66")
	}
	// синтетична історія 24 год
	m := ta.metrics
	m.mu.Lock()
	now := time.Now().Truncate(time.Minute).Unix()
	rnd := rand.New(rand.NewSource(1))
	for i := 1440; i >= 1; i-- {
		tm := now - int64(i)*60
		if i > 300 && i < 306 { // перезапуск
			continue
		}
		wave := 1 + 0.3*math.Sin(float64(i)/120)
		mi := Minute{T: tm, OK: int64(80 * wave), Streams: 10 + rnd.Intn(4), Webhook: [2]float64{-1, -1}, Delivery: [2]float64{-1, -1}, Full: [2]float64{-1, -1}}
		if rnd.Intn(30) == 0 {
			mi.Unauth = int64(rnd.Intn(5))
		}
		if i == 400 {
			mi.Limited = 25
		}
		if rnd.Intn(4) == 0 {
			w := 3000 + rnd.Float64()*2500
			if i > 900 && i < 930 {
				w = 12000
			}
			d := 5 + rnd.Float64()*20
			mi.Webhook, mi.Delivery, mi.Full = [2]float64{w, w * 2}, [2]float64{d, d * 2}, [2]float64{w + d, w*2 + d}
			mi.Events = int64(1 + rnd.Intn(5))
		}
		m.hist = append(m.hist, mi)
		m.tokHist[tk.ID] = append(m.tokHist[tk.ID], TokenMinute{T: tm, Req: int64(1 + rnd.Intn(3))})
	}
	m.mu.Unlock()
	ta.journal.Add("service", "", "Службу запущено (alertcast %s)", version)
	ta.journal.Add("data", "", "Стан перечитано з alertd повністю (resync)")

}

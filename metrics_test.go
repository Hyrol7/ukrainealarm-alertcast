package main

import (
	"testing"
	"time"
)

// Хвилина закривається, коли годинник переходить межу; тестовий годинник — керований.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func TestMetricsRollAndPersist(t *testing.T) {
	ta := newTestApp(t)
	clk := &fakeClock{t: time.Now().Truncate(time.Minute).Add(10 * time.Second)}
	m, err := NewMetrics(ta.tokens.db)
	if err != nil {
		t.Fatal(err)
	}
	m.now = clk.now
	m.cur.T = clk.t.Truncate(time.Minute).Unix()
	m.Request("tk1", 200)
	m.Request("tk1", 200)
	m.Request("tk1", 429)
	m.Request("", 401)
	m.Request("tk2", 403)
	for i := 1; i <= 10; i++ {
		m.Delivered(time.Duration(i)*time.Millisecond, time.Duration(i)*time.Second, i%2 == 0)
		m.Event(time.Duration(i)*100*time.Millisecond, true)
	}
	m.Event(-time.Second, true) // некоректний годинник — не враховується
	m.Tick(7)
	if h := m.History(); len(h) != 0 {
		t.Fatalf("minute closed too early: %+v", h)
	}
	clk.t = clk.t.Add(time.Minute)
	h := m.History()
	if len(h) != 1 {
		t.Fatalf("history: %+v", h)
	}
	x := h[0]
	if x.OK != 2 || x.Limited != 1 || x.Unauth != 1 || x.Forbid != 1 || x.Streams != 7 || x.Events != 11 {
		t.Fatalf("minute: %+v", x)
	}
	if x.Delivery != [2]float64{5, 9} || x.Webhook != [2]float64{500, 900} || x.Full != [2]float64{6000, 8000} {
		t.Fatalf("percentiles: %+v %+v %+v", x.Delivery, x.Webhook, x.Full)
	}
	sums := m.TokenSums()
	if sums["tk1"].Req != 2 || sums["tk1"].Limited != 1 || sums["tk2"].Forbid != 1 || len(sums) != 2 {
		t.Fatalf("token sums: %+v", sums)
	}
	// порожня хвилина: затримки -1 (немає даних), а не 0
	clk.t = clk.t.Add(time.Minute)
	if h := m.History(); len(h) != 2 || h[1].Delivery[0] != -1 {
		t.Fatalf("empty minute: %+v", h)
	}
	// після перезапуску — з БД
	m.Wait()
	m2, err := NewMetrics(ta.tokens.db)
	if err != nil {
		t.Fatal(err)
	}
	if h := m2.history(); len(h) != 2 || h[0].OK != 2 || len(m2.tokHist["tk1"]) != 1 {
		t.Fatalf("reload: %+v %+v", h, m2.tokHist)
	}
	// старше 24 год — викидається
	clk.t = clk.t.Add(25 * time.Hour)
	m.Request("tk1", 200)
	if h := m.History(); len(h) != 0 || len(m.TokenHistory("tk2")) != 0 || len(m.TokenHistory("tk1")) != 1 {
		t.Fatalf("window: %d %+v", len(h), m.TokenHistory("tk2"))
	}
}

func (m *Metrics) history() []Minute { m.mu.Lock(); defer m.mu.Unlock(); return m.hist }

func TestMetricsFromTraffic(t *testing.T) {
	ta := newTestApp(t)
	secret, tk := ta.token(t, func(s *TokenSpec) { s.Regions = &[]string{"101"} })
	do(t, ta.pub.URL, "/api/v1/status?regions=101", secret)
	do(t, ta.pub.URL, "/api/v1/status?regions=20", secret)
	do(t, ta.pub.URL, "/api/v1/me", "ac_bad")
	c := openStream(t, ta.pub.URL, "/api/v1/stream?regions=101", secret)
	if e := c.next(t, 2*time.Second); e.name != "snapshot" {
		t.Fatalf("first: %+v", e)
	}
	waitFor(t, "stream registered", func() bool { return len(ta.hub.List(tk.ID)) == 1 })
	if s := ta.hub.List(tk.ID)[0]; s.Listener != "public" || s.Regions[0] != "101" {
		t.Fatalf("stream info: %+v", s)
	}
	ta.fake.push("10", "AIR", lv("Red", 0))
	for e := c.next(t, 2*time.Second); e.name != "update"; e = c.next(t, 2*time.Second) {
	}
	waitFor(t, "sent counted", func() bool { return ta.hub.List(tk.ID)[0].Sent == 1 })
	ta.metrics.mu.Lock()
	cur, nd := ta.metrics.cur, len(ta.metrics.deliv)
	ta.metrics.mu.Unlock()
	if cur.OK < 2 || cur.Forbid != 1 || cur.Unauth != 1 || cur.Events < 1 || nd != 1 {
		t.Fatalf("metrics: %+v deliv=%d", cur, nd)
	}
	if s := ta.metrics.TokenSums()[tk.ID]; s.Forbid != 1 || s.Req < 2 {
		t.Fatalf("token: %+v", s)
	}
	// блокування адреси потрапляє в журнал
	for i := 0; i < ta.cfg.AuthFailLimit; i++ {
		do(t, ta.pub.URL, "/api/v1/me", "ac_bad", "X-Forwarded-For", "203.0.113.9")
	}
	if j := ta.journal.Recent(10, "ban"); len(j) == 0 {
		t.Fatalf("no ban in journal: %+v", ta.journal.Recent(10, ""))
	}
}

func TestJournalPersistAndPrune(t *testing.T) {
	ta := newTestApp(t)
	ta.journal.Add("token", "10.77.0.2", "Створено «%s»", "лампа")
	var nilJ *Journal
	nilJ.Add("x", "", "ignored") // nil-безпечно
	j2, err := NewJournal(ta.tokens.db)
	if err != nil {
		t.Fatal(err)
	}
	r := j2.Recent(5, "token")
	if len(r) != 1 || r[0].Text != "Створено «лампа»" || r[0].IP != "10.77.0.2" {
		t.Fatalf("reload: %+v", r)
	}
	j2.Prune(time.Now().Add(31 * 24 * time.Hour))
	if j3, _ := NewJournal(ta.tokens.db); len(j3.Recent(5, "")) != 0 {
		t.Fatalf("not pruned")
	}
}

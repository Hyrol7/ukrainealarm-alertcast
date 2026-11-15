package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func nextAlert(t *testing.T, c *sseClient) FeedEvent {
	t.Helper()
	for {
		e := c.next(t, 3*time.Second)
		if e.name == "meta" {
			continue
		}
		if e.name != "alert" {
			t.Fatalf("want alert, got %s: %s", e.name, e.data)
		}
		var f FeedEvent
		if err := json.Unmarshal([]byte(e.data), &f); err != nil {
			t.Fatal(err)
		}
		return f
	}
}

func TestEventsFeed(t *testing.T) {
	ta := newTestApp(t)
	ta.fake.push("2", "AIR", lv("Red", 0))
	waitFor(t, "applied", func() bool { return ta.state.ActiveCount() == 1 })
	secret, _ := ta.token(t)
	c := openStream(t, ta.pub.URL, "/api/v1/events", secret)
	e := c.next(t, 2*time.Second)
	var snap eventsSnapshot
	json.Unmarshal([]byte(e.data), &snap)
	if e.name != "snapshot" || len(snap.Alerts) != 1 || snap.Alerts[0].Region != "2" || snap.Alerts[0].Change != "active" ||
		snap.Alerts[0].StateName != "Область 2" || snap.Alerts[0].Levels[0] != "red" || snap.Stale {
		t.Fatalf("snapshot: %s %s", e.name, e.data)
	}
	// громада: район і область заповнені; рівні від найвищого
	ta.fake.push("121", "AIR", lv("Yellow", 1), lv("Red", 2))
	f := nextAlert(t, c)
	if f.Change != "start" || f.Region != "121" || f.RegionName != "Громада 121" || f.RegionType != "Community" ||
		f.District != "12" || f.State != "1" || f.StateName != "Область 1" || strings.Join(f.Levels, ",") != "red,yellow" ||
		f.Type != "AIR" || f.Seq == 0 || f.Test {
		t.Fatalf("start: %+v", f)
	}
	// рівень змінився — update; ті самі рівні — без події
	ta.fake.push("121", "AIR", lv("Yellow", 3))
	if f2 := nextAlert(t, c); f2.Change != "update" || strings.Join(f2.Levels, ",") != "yellow" || f2.Seq <= f.Seq {
		t.Fatalf("update: %+v", f2)
	}
	ta.fake.push("121", "AIR", lv("Yellow", 4))
	ta.fake.push("2", "AIR")
	if f3 := nextAlert(t, c); f3.Change != "end" || f3.Region != "2" || len(f3.Levels) != 0 {
		t.Fatalf("end (and no event for same levels): %+v", f3)
	}
	// тестова область — не для «усіх регіонів» без ?test=1
	ta.admin(adminReq{Op: "test-set", Region: "990101", Level: "red"})
	ta.fake.push("20", "ARTILLERY", lv("", 0))
	if f4 := nextAlert(t, c); f4.Region != "20" {
		t.Fatalf("test region leaked: %+v", f4)
	}
	// перечитаний стан alertd (resync): різниця приходить подіями
	ta.state.Replace([]*Alert{al("20", "ARTILLERY", 0, lv("", 0)), al("100", "AIR", 5, lv("Red", 5))})
	got := map[string]string{}
	for i := 0; i < 2; i++ {
		f := nextAlert(t, c)
		got[f.Region+"/"+f.Change] = f.Source
	}
	if got["121/end"] != "resync" || got["100/start"] != "resync" {
		t.Fatalf("resync diff: %v", got)
	}
	c.none(t, 300*time.Millisecond)
}

func TestEventsFiltering(t *testing.T) {
	ta := newTestApp(t)
	limited, _ := ta.token(t, func(s *TokenSpec) { s.Regions = &[]string{"1", "990100"} })
	all, _ := ta.token(t)
	cl := openStream(t, ta.pub.URL, "/api/v1/events", limited)
	ca := openStream(t, ta.pub.URL, "/api/v1/events?test=1", all)
	cn := openStream(t, ta.pub.URL, "/api/v1/events?test=1", limited) // ?test=1 не розширює обмежений токен
	for _, c := range []*sseClient{cl, ca, cn} {
		if e := c.next(t, 2*time.Second); e.name != "snapshot" {
			t.Fatalf("first: %+v", e)
		}
	}
	ta.fake.push("20", "AIR", lv("Red", 0))
	ta.fake.push("110", "AIR", lv("Red", 0))
	waitFor(t, "applied", func() bool { return ta.state.ActiveCount() == 2 })
	ta.admin(adminReq{Op: "test-set", Region: "990101", Level: "yellow"})
	ta.admin(adminReq{Op: "test-set", Region: "990200", Level: "yellow"})
	for _, c := range []*sseClient{cl, cn} {
		if f := nextAlert(t, c); f.Region != "110" {
			t.Fatalf("limited got %+v", f)
		}
		if f := nextAlert(t, c); f.Region != "990101" || !f.Test || f.Source != "test" {
			t.Fatalf("limited test: %+v", f)
		}
		c.none(t, 200*time.Millisecond) // 20 і 990200 — поза дозволеними
	}
	var regs []string
	for i := 0; i < 4; i++ {
		regs = append(regs, nextAlert(t, ca).Region)
	}
	if strings.Join(regs, ",") != "20,110,990101,990200" {
		t.Fatalf("all+test: %v", regs)
	}
}

func TestEventsLimitsAndBye(t *testing.T) {
	ta := newTestApp(t)
	secret, tk := ta.token(t, func(s *TokenSpec) { s.Streams = ptr(1) })
	c := openStream(t, ta.pub.URL, "/api/v1/events", secret)
	c.next(t, 2*time.Second)
	if c2 := openStream(t, ta.pub.URL, "/api/v1/events", secret); c2.code != 429 {
		t.Fatalf("second stream: %d", c2.code)
	}
	if s := ta.hub.List(tk.ID); len(s) != 1 {
		t.Fatalf("streams: %+v", s)
	}
	ta.admin(adminReq{Op: "revoke", ID: tk.ID})
	if e := c.next(t, 2*time.Second); e.name != "bye" {
		t.Fatalf("bye: %+v", e)
	}
	if r := do(t, ta.pub.URL, "/api/v1/events", ""); r.code != 401 {
		t.Fatalf("no token: %d", r.code)
	}
}

func TestFeedRing(t *testing.T) {
	f := NewFeed()
	for i := 0; i < feedCap+10; i++ {
		f.append(FeedEvent{Region: "1"})
	}
	if _, lost, _ := f.Since(5); !lost {
		t.Fatal("overwritten events not reported lost")
	}
	evs, lost, _ := f.Since(f.Next() - 3)
	if lost || len(evs) != 3 || evs[2].Seq != f.Next()-1 || evs[0].Seq != f.Next()-3 {
		t.Fatalf("tail: %v %+v", lost, evs)
	}
	if evs, lost, _ := f.Since(f.Next()); lost || len(evs) != 0 {
		t.Fatal("empty tail")
	}
	_, _, wake := f.Since(f.Next())
	f.append(FeedEvent{})
	select {
	case <-wake:
	default:
		t.Fatal("no wake")
	}
}

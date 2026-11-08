package main

import (
	"strings"
	"testing"
	"time"
)

func TestTestRegionIsolation(t *testing.T) {
	ta := newTestApp(t)
	all, _ := ta.token(t)                                                               // «усі регіони»
	esp, _ := ta.token(t, func(s *TokenSpec) { s.Regions = &[]string{"10", "990000"} }) // явно
	if err := ta.state.SetTestAlert("990100", "AIR", "red", time.Now()); err != nil {
		t.Fatal(err)
	}
	ta.hub.Notify(testRoot)
	// токен «усі регіони» тестової області не бачить
	if r := do(t, ta.pub.URL, "/api/v1/status?regions=990100", all); r.code != 403 {
		t.Fatalf("all-regions token sees test region: %d", r.code)
	}
	// явний доступ: стан з ієрархією і позначкою test
	var r statusResp
	do(t, ta.pub.URL, "/api/v1/status?regions=990101,990000,990200,10", esp).json(t, &r)
	c, o, d2, real := r.Regions["990101"], r.Regions["990000"], r.Regions["990200"], r.Regions["10"]
	if !c.Test || c.State != "active" || c.Level != "red" || !o.Test || o.State != "partial" || d2.State != "none" || real.Test {
		t.Fatalf("test hierarchy: %+v", r.Regions)
	}
	// у сумісному v3 її немає зовсім
	for _, p := range []string{"/api/v3/alerts", "/api/v3/regions"} {
		if b := do(t, ta.pub.URL, p, esp).body; strings.Contains(b, "9901") || strings.Contains(b, "Тестов") {
			t.Fatalf("%s leaks test region: %.300s", p, b)
		}
	}
	if r := do(t, ta.pub.URL, "/api/v3/alerts/990100", esp); r.code != 404 {
		t.Fatalf("v3 one test region: %d", r.code)
	}
	if n := ta.state.ActiveCount(); n != 0 {
		t.Fatalf("test alerts counted as real: %d", n)
	}
	// у списку регіонів — з позначкою
	if b := do(t, ta.pub.URL, "/api/v1/regions", all).body; !strings.Contains(b, `{"test":true,"id":"990000"`) {
		t.Fatal("regions list lacks flagged test region")
	}
}

// alertd не може змінити тестову область, а повний знімок з alertd її не стирає.
func TestTestRegionSurvivesAlertd(t *testing.T) {
	ta := newTestApp(t)
	ta.state.SetTestAlert("990100", "AIR", "yellow", time.Now())
	ta.fake.push("990100", "AIR") // «відбій» від alertd — ігнорується
	ta.fake.push("990200", "AIR", lv("Red", 0))
	ta.fake.push("10", "AIR", lv("Red", 0))
	waitFor(t, "real alert", func() bool { return ta.state.Status("10").State == "active" })
	if ta.state.Status("990100").Level != "yellow" || ta.state.Status("990200").State != "none" {
		t.Fatalf("alertd changed test region: %+v %+v", ta.state.Status("990100"), ta.state.Status("990200"))
	}
	ta.fake.send("event: resync\ndata: {}\n\n") // повний знімок
	waitFor(t, "resync", func() bool { return ta.src.resyncs.Load() > 0 })
	time.Sleep(100 * time.Millisecond)
	if ta.state.Status("990100").Level != "yellow" {
		t.Fatal("snapshot wiped test region")
	}
}

func TestTestRegionStreamAndTTL(t *testing.T) {
	ta := newTestApp(t)
	tok, _ := ta.token(t, func(s *TokenSpec) { s.Regions = &[]string{"990100"} })
	s := openStream(t, ta.pub.URL, "/api/v1/stream?regions=990101", tok)
	if e := s.next(t, time.Second); !strings.Contains(e.data, `"test":true`) || !strings.Contains(e.data, `"state":"none"`) {
		t.Fatalf("snapshot: %+v", e)
	}
	r := ta.admin(adminReq{Op: "test-set", Region: "990100", Level: "red"})
	if !r.OK || len(r.Test) != 1 {
		t.Fatalf("set: %+v", r)
	}
	if e := s.next(t, time.Second); e.name != "update" || !strings.Contains(e.data, `"level":"red"`) || !strings.Contains(e.data, `"test":true`) {
		t.Fatalf("update: %+v", e)
	}
	// автоскидання: тривога без змін довше за TTL
	if n := ta.state.ClearTest(time.Now().Add(testTTL+time.Minute), testTTL); n != 1 {
		t.Fatalf("ttl clear: %d", n)
	}
	ta.hub.Notify(testRoot)
	if e := s.next(t, time.Second); e.name != "update" || !strings.Contains(e.data, `"state":"none"`) {
		t.Fatalf("after ttl: %+v", e)
	}
	for _, bad := range []adminReq{
		{Op: "test-set", Region: "10", Level: "red"},
		{Op: "test-set", Region: "990100", Level: "purple"},
		{Op: "test-set", Region: "990100", Level: "red", Type: "ZOMBIE"},
	} {
		if ta.admin(bad).OK {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestTestRegionDisabledOnClash(t *testing.T) {
	rs := append(sampleRegions(), Region{ID: "990000", Name: "справжній"})
	if got := withTestRegions(rs); len(got) != len(rs) {
		t.Fatal("test region must yield to a real region with the same ID")
	}
}

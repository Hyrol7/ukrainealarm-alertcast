package main

import (
	"strings"
	"testing"
	"time"
)

func TestPublicIndex(t *testing.T) {
	ta := newTestApp(t)
	ta.fake.push("2", "AIR", lv("Red", 0), lv("Yellow", 1))
	ta.fake.push("11", "ARTILLERY", lv("", 0))
	ta.fake.push("121", "AIR", lv("Yellow", 0))
	waitFor(t, "applied", func() bool { return ta.state.ActiveCount() == 3 })
	ta.admin(adminReq{Op: "test-set", Region: "990100", Level: "red"})
	r := do(t, ta.pub.URL, "/", "")
	tag := r.hdr.Get("ETag")
	if r.code != 200 || tag == "" {
		t.Fatalf("index: %d %v", r.code, r.hdr)
	}
	b := r.body
	order := []string{"Область 1", "частково", "Район 11", "артобстріл", "не вказано", "Громада 121", "БпЛА", "Область 2", "повітряна", "ракети, БпЛА"}
	pos := 0
	for _, w := range order {
		i := strings.Index(b[pos:], w)
		if i < 0 {
			t.Fatalf("missing/out of order %q in:\n%s", w, b)
		}
		pos += i
	}
	if strings.Contains(b, "Тестов") || strings.Contains(b, "9901") {
		t.Fatal("test region on public page")
	}
	if !strings.Contains(b, "областей: 2, районів: 1") || !strings.Contains(b, "дані свіжі") {
		t.Fatalf("summary:\n%s", b)
	}
	if !strings.Contains(b, `<tr class="top"><td>Область 2</td><td>повітряна</td><td>ракети, БпЛА</td><td>`+sinceText(t0, time.Now())) {
		t.Fatalf("row:\n%s", b)
	}
	if r := do(t, ta.pub.URL, "/", "", "If-None-Match", tag); r.code != 304 || r.body != "" {
		t.Fatalf("304: %d", r.code)
	}
	// зміна стану — новий ETag; тестова область ETag не впливає на видимий вміст, але не ламає
	ta.fake.push("2", "AIR")
	waitFor(t, "ended", func() bool { return ta.state.ActiveCount() == 2 })
	r2 := do(t, ta.pub.URL, "/", "", "If-None-Match", tag)
	if r2.code != 200 || r2.hdr.Get("ETag") == tag || strings.Contains(r2.body, "ракети, БпЛА") {
		t.Fatalf("after change: %d", r2.code)
	}
	if sinceText(time.Now(), time.Now()) == "" || sinceText(time.Time{}, time.Now()) != "" {
		t.Fatal("sinceText")
	}
}

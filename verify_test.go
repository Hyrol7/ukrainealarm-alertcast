package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Звірка: що збігається — збігається; розбіжність (пропущена, зайва, інший рівень) — видно.
func TestVerifyCompare(t *testing.T) {
	s := newTestState(al("10", "AIR", 0, lv("Red", 0)))
	b, _ := json.Marshal(s.V3All())
	var ours []cmpRecord
	json.Unmarshal(b, &ours)
	// «ukrainealarm» — те саме, але regionId числами (бувають і такі відповіді)
	up := strings.NewReplacer(`"regionId":"10"`, `"regionId":10`, `"regionId":"101"`, `"regionId":101`).Replace(string(b))
	var upRecs []cmpRecord
	if err := json.Unmarshal([]byte(up), &upRecs); err != nil {
		t.Fatal(err)
	}
	us, names := alertSet(upRecs)
	os, _ := alertSet(ours)
	if d := compareSets(us, os, names); len(d) != 0 {
		t.Fatalf("identical data differ: %+v", d)
	}
	// інший рівень у громаді 100 і зайва тривога в 2 — дві розбіжності
	s2 := newTestState(al("10", "AIR", 0, lv("Yellow", 0)), al("2", "AIR", 0))
	b2, _ := json.Marshal(s2.V3All())
	var ours2 []cmpRecord
	json.Unmarshal(b2, &ours2)
	os2, _ := alertSet(ours2)
	d := compareSets(us, os2, names)
	if len(d) < 6 || d[0].Region != "1" || len(d[0].Missing) != 1 || len(d[0].Extra) != 1 {
		t.Fatalf("diff: %+v", d)
	}
}

func TestFetchUpstreamRateLimitRetry(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "tok" {
			w.WriteHeader(401)
			return
		}
		if calls == 1 {
			w.WriteHeader(429)
			fmt.Fprint(w, "Please wait 0 seconds")
			return
		}
		fmt.Fprint(w, `[{"regionId":"32","regionName":"x","activeAlerts":[]}]`)
	}))
	defer srv.Close()
	t0 := time.Now()
	recs, err := fetchUpstream(srv.URL, "tok")
	if err != nil || len(recs) != 1 || calls != 2 || time.Since(t0) > 5*time.Second {
		t.Fatalf("%v %d %d", err, len(recs), calls)
	}
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "null") }))
	defer srv2.Close()
	if _, err := fetchUpstream(srv2.URL, "tok"); err == nil {
		t.Fatal("null must not be treated as «no alerts»")
	}
}

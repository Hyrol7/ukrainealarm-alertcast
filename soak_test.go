package main

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// SOAK=1: тисяча потоків по різних регіонах, серія змін; затримка доставки й пам'ять.
func TestSoakStreams(t *testing.T) {
	if os.Getenv("SOAK") == "" {
		t.Skip("SOAK not set")
	}
	const n = 1000
	ta := newTestApp(t, func(c *Config, s *Source) { c.MaxStreams, c.MaxStreamsIP = 2000, 2000 })
	tok, _ := ta.token(t, func(s *TokenSpec) { s.Streams = ptr(100) })
	toks := []string{tok}
	for i := 1; i < n/100; i++ {
		x, _ := ta.token(t, func(s *TokenSpec) { s.Streams = ptr(100) })
		toks = append(toks, x)
	}
	ids := []string{}
	for _, r := range sampleRegions() {
		ids = append(ids, r.ID)
	}
	var ms0 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&ms0)
	streams := make([]*sseClient, n)
	for i := range streams {
		streams[i] = openStream(t, ta.pub.URL, "/api/v1/stream?regions="+ids[i%len(ids)]+",1,2", toks[i/100])
		if streams[i].code != 200 {
			t.Fatalf("stream %d: %d", i, streams[i].code)
		}
		streams[i].next(t, 5*time.Second)
	}
	// кожен потік стежить за областю 1 → кожна зміна в області 1 має дійти до всіх
	var lat []time.Duration
	var mu sync.Mutex
	for round := 0; round < 20; round++ {
		lvl := []string{"Red", "Yellow"}[round%2]
		start := time.Now()
		ta.fake.push("1", "AIR", lv(lvl, round))
		var wg sync.WaitGroup
		for _, s := range streams {
			wg.Add(1)
			go func(s *sseClient) {
				defer wg.Done()
				want := `"level":"` + strings.ToLower(lvl) + `"`
				for {
					select {
					case e := <-s.ev:
						if strings.Contains(e.data, `"id":"1"`) && strings.Contains(e.data, want) {
							mu.Lock()
							lat = append(lat, time.Since(start))
							mu.Unlock()
							return
						}
					case <-time.After(5 * time.Second):
						t.Errorf("round %d: stream missed the change", round)
						return
					}
				}
			}(s)
		}
		wg.Wait()
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	t.Logf("%d streams × 20 changes: delivery p50 %s, p99 %s, max %s; heap +%d MB, goroutines %d",
		n, lat[len(lat)/2].Round(time.Microsecond), lat[len(lat)*99/100].Round(time.Microsecond), lat[len(lat)-1].Round(time.Microsecond),
		(ms.HeapAlloc-ms0.HeapAlloc)>>20, runtime.NumGoroutine())
	fmt.Fprint(os.Stderr, "")
}

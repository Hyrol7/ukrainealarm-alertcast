package main

import (
	"sort"
	"sync"
	"time"
)

// Стрічка змін для /api/v1/events: кожна зміна окремої тривоги (регіон × тип) — подія
// start | update | end, у порядку застосування. Кільцевий буфер у пам'яті; підписник читає
// зі свого курсора. Хто відстав більше, ніж вміщує буфер, отримує новий знімок (resync) —
// повільний клієнт ніколи не гальмує інших і не отримує «дірявої» послідовності.

const feedCap = 8192

// FeedEvent — зміна однієї тривоги. Рівні — від найвищого: red, yellow, unknown.
type FeedEvent struct {
	Seq        uint64    `json:"seq,omitempty"` // у знімку немає
	Version    uint64    `json:"version"`
	Change     string    `json:"change"` // start | update | end
	Region     string    `json:"regionId"`
	RegionName string    `json:"regionName"`
	RegionType string    `json:"regionType"`
	District   string    `json:"districtId,omitempty"` // район (для громади)
	State      string    `json:"stateId"`              // область
	StateName  string    `json:"stateName"`
	Type       string    `json:"type"`
	Levels     []string  `json:"levels"`
	Since      time.Time `json:"since,omitzero"` // початок тривоги
	At         time.Time `json:"at"`             // коли сталася зміна (час ukrainealarm, якщо відомий)
	Source     string    `json:"source,omitempty"`
	Test       bool      `json:"test,omitempty"`
}

type Feed struct {
	mu   sync.Mutex
	ring []FeedEvent
	next uint64        // seq наступної події; перша — 1
	wake chan struct{} // закривається на кожну нову подію
}

func NewFeed() *Feed {
	return &Feed{ring: make([]FeedEvent, 0, 256), next: 1, wake: make(chan struct{})}
}

// append — викликається під s.mu (запис) стану: порядок подій = порядок змін.
func (f *Feed) append(evs ...FeedEvent) {
	if f == nil || len(evs) == 0 {
		return
	}
	f.mu.Lock()
	for _, e := range evs {
		e.Seq = f.next
		f.next++
		if len(f.ring) < feedCap {
			f.ring = append(f.ring, e)
		} else {
			f.ring[(e.Seq-1)%feedCap] = e
		}
	}
	close(f.wake)
	f.wake = make(chan struct{})
	f.mu.Unlock()
}

// Next — seq наступної події (курсор «з цього моменту»).
func (f *Feed) Next() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.next
}

// Since — події з seq ≥ from; lost — частина вже витіснена з буфера; wake — сигнал нових.
func (f *Feed) Since(from uint64) (out []FeedEvent, lost bool, wake <-chan struct{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	oldest := uint64(1)
	if f.next > feedCap {
		oldest = f.next - feedCap
	}
	if from < oldest {
		return nil, true, f.wake
	}
	for s := from; s < f.next; s++ {
		out = append(out, f.ring[(s-1)%feedCap])
	}
	return out, false, f.wake
}

// ---------- події з боку стану (під s.mu) ----------

func levelList(ls []Level) []string {
	set := map[string]bool{}
	for _, l := range ls {
		set[normLevel(l.Level)] = true
	}
	out := []string{}
	for _, k := range []string{"red", "yellow", "unknown"} {
		if set[k] {
			out = append(out, k)
		}
	}
	return out
}

func sameLevels(a, b []Level) bool {
	x, y := levelList(a), levelList(b)
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// feedEventLocked — подія для тривоги a (під s.mu).
func (s *State) feedEventLocked(change string, a *Alert, at time.Time, source string) FeedEvent {
	t := s.tree
	r := t.byID[a.Region]
	e := FeedEvent{Version: s.version, Change: change, Region: a.Region, RegionName: r.Name, RegionType: r.Type,
		State: t.stateOf(a.Region), Type: a.Type, Levels: levelList(a.Levels), Since: a.Since, At: at, Source: source,
		Test: isTestRegion(a.Region)}
	if change == "end" {
		e.Levels = []string{}
	}
	if st, ok := t.byID[e.State]; ok {
		e.StateName = st.Name
	}
	if r.Type == "Community" && r.ParentID != "" && r.ParentID != e.State {
		e.District = r.ParentID
	}
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	return e
}

// FeedSnapshot — усі чинні тривоги й курсор, з якого читати далі (узгоджено, під одним замком).
func (s *State) FeedSnapshot(allow func(string) bool) (alerts []FeedEvent, version, next uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	alerts = []FeedEvent{}
	for id, as := range s.byRegion {
		if !allow(id) {
			continue
		}
		for _, a := range as {
			e := s.feedEventLocked("active", a, a.lastUpdate(), "")
			alerts = append(alerts, e)
		}
	}
	sort.Slice(alerts, func(i, j int) bool {
		if alerts[i].Region != alerts[j].Region {
			return alerts[i].Region < alerts[j].Region
		}
		return alerts[i].Type < alerts[j].Type
	})
	return alerts, s.version, s.feed.Next()
}

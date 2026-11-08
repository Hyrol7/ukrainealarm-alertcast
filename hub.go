package main

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Sub — один потік /api/v1/stream. Черги подій немає: зміна лише ставить прапорець dirty,
// а потік сам перераховує свої регіони й надсилає те, що справді змінилось. Тож повільний
// клієнт нікого не гальмує, а зміна не може загубитися через переповнений буфер.
type Sub struct {
	Regions  []string
	TokenID  string
	IP       string
	Listener string
	Opened   time.Time
	Sent     atomic.Int64

	states map[string]bool
	dirty  chan struct{} // cap 1: «щось змінилось — перерахуй»
	kick   chan struct{} // закривається, коли потік треба завершити (токен змінено/відкликано)
	once   sync.Once
}

func newSub(regions []string, tokenID, ip string) *Sub {
	return &Sub{Regions: regions, TokenID: tokenID, IP: ip, Opened: time.Now(), dirty: make(chan struct{}, 1), kick: make(chan struct{})}
}

func (s *Sub) mark() {
	select {
	case s.dirty <- struct{}{}:
	default:
	}
}

func (s *Sub) close() { s.once.Do(func() { close(s.kick) }) }

// Hub — усі відкриті потоки; індекс за областями, ліміти на токен, IP і загалом.
type Hub struct {
	mu      sync.Mutex
	subs    map[*Sub]struct{}
	byState map[string]map[*Sub]struct{}
	byToken map[string]int
	byIP    map[string]int
	stateOf func(string) string

	MaxTotal, MaxPerIP int
}

func NewHub(stateOf func(string) string, maxTotal, maxPerIP int) *Hub {
	return &Hub{subs: map[*Sub]struct{}{}, byState: map[string]map[*Sub]struct{}{},
		byToken: map[string]int{}, byIP: map[string]int{}, stateOf: stateOf, MaxTotal: maxTotal, MaxPerIP: maxPerIP}
}

// Add реєструє потік. Причина відмови: "total", "ip", "token" ("" — прийнято).
func (h *Hub) Add(s *Sub, tokenLimit int) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case len(h.subs) >= h.MaxTotal:
		return "total"
	case h.byIP[s.IP] >= h.MaxPerIP:
		return "ip"
	case h.byToken[s.TokenID] >= tokenLimit:
		return "token"
	}
	h.subs[s] = struct{}{}
	h.byToken[s.TokenID]++
	h.byIP[s.IP]++
	h.indexLocked(s)
	return ""
}

func (h *Hub) indexLocked(s *Sub) {
	s.states = map[string]bool{}
	for _, r := range s.Regions {
		st := h.stateOf(r)
		s.states[st] = true
		m := h.byState[st]
		if m == nil {
			m = map[*Sub]struct{}{}
			h.byState[st] = m
		}
		m[s] = struct{}{}
	}
}

func (h *Hub) unindexLocked(s *Sub) {
	for st := range s.states {
		if m := h.byState[st]; m != nil {
			delete(m, s)
			if len(m) == 0 {
				delete(h.byState, st)
			}
		}
	}
}

func (h *Hub) Remove(s *Sub) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.subs[s]; !ok {
		return
	}
	delete(h.subs, s)
	h.unindexLocked(s)
	if h.byToken[s.TokenID]--; h.byToken[s.TokenID] <= 0 {
		delete(h.byToken, s.TokenID)
	}
	if h.byIP[s.IP]--; h.byIP[s.IP] <= 0 {
		delete(h.byIP, s.IP)
	}
}

// Notify — змінилось щось в області st: позначити потоки, що стежать за її регіонами.
func (h *Hub) Notify(st string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.byState[st] {
		s.mark()
	}
}

// NotifyAll — змінилось усе (новий знімок, свіжість даних).
func (h *Hub) NotifyAll() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.subs {
		s.mark()
	}
}

// Reindex — дерево регіонів змінилось: області потоків могли змінитись.
func (h *Hub) Reindex() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.byState = map[string]map[*Sub]struct{}{}
	for s := range h.subs {
		h.indexLocked(s)
		s.mark()
	}
}

// Kick завершує потоки токена (його змінили або відкликали). "" — усі потоки.
func (h *Hub) Kick(tokenID string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for s := range h.subs {
		if tokenID == "" || s.TokenID == tokenID {
			s.close()
			n++
		}
	}
	return n
}

func (h *Hub) Count() (total int, byToken map[string]int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	byToken = make(map[string]int, len(h.byToken))
	for k, v := range h.byToken {
		byToken[k] = v
	}
	return len(h.subs), byToken
}

// StreamInfo — відкритий потік (для адмінки).
type StreamInfo struct {
	TokenID  string    `json:"token"`
	IP       string    `json:"ip"`
	Listener string    `json:"listener"`
	Regions  []string  `json:"regions"`
	Opened   time.Time `json:"opened"`
	Sent     int64     `json:"sent"`
}

// List — відкриті потоки токена ("" — усі).
func (h *Hub) List(tokenID string) []StreamInfo {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []StreamInfo
	for s := range h.subs {
		if tokenID == "" || s.TokenID == tokenID {
			out = append(out, StreamInfo{TokenID: s.TokenID, IP: s.IP, Listener: s.Listener, Regions: s.Regions, Opened: s.Opened, Sent: s.Sent.Load()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Opened.Before(out[j].Opened) })
	return out
}

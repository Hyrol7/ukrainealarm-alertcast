package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Source — зв'язок з alertd: дерево регіонів (/regions), знімок (/state) і потік змін
// (/events). Після обриву перепідключається з Last-Event-ID; якщо alertd просить resync
// або змінився epoch (нова БД alertd) — перечитує знімок повністю.
type Source struct {
	base  string
	hc    *http.Client
	state *State
	hub   *Hub

	epoch  string
	seq    int64
	epochV atomic.Value // string: копія epoch для /stats

	connected    atomic.Bool
	connChanged  atomic.Int64 // unix ms останньої зміни connected
	lastContact  atomic.Int64 // unix ms: будь-які байти від alertd
	verifiedAt   atomic.Int64 // unix s: остання звірка alertd з API ukrainealarm (з /health)
	everLoaded   atomic.Bool
	reconnects   atomic.Int64
	resyncs      atomic.Int64
	applied      atomic.Int64
	lastErr      atomic.Value // string
	staleAfter   time.Duration
	downGrace    time.Duration // скільки потік з alertd може бути розірваний, поки дані ще вважаються свіжими
	healthEvery  time.Duration
	idleTimeout  time.Duration
	regionsEvery time.Duration
	lastStale    atomic.Bool
	metrics      *Metrics
	journal      *Journal
}

func NewSource(base string, state *State, hub *Hub, staleAfter time.Duration) *Source {
	s := &Source{
		base: strings.TrimRight(base, "/"), state: state, hub: hub,
		hc: &http.Client{
			// alertd — лише loopback; перенаправлень не виконуємо
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		staleAfter: staleAfter, downGrace: 20 * time.Second, healthEvery: 10 * time.Second,
		idleTimeout: 45 * time.Second, regionsEvery: 6 * time.Hour,
	}
	s.lastErr.Store("")
	s.epochV.Store("")
	s.lastStale.Store(true)
	return s
}

var errResync = errors.New("resync")

// Run — головний цикл. Повертається лише після скасування ctx.
func (s *Source) Run(ctx context.Context) {
	go s.healthLoop(ctx)
	go s.staleLoop(ctx)
	backoff := 200 * time.Millisecond
	sleep := func() bool {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(backoff):
		}
		if backoff < 5*time.Second {
			backoff *= 2
		}
		return true
	}
	// 1) дерево регіонів
	for s.state.Tree().Len() == 0 {
		if err := s.loadRegions(ctx); err != nil {
			s.setErr(err)
			if !sleep() {
				return
			}
		}
	}
	go s.regionsLoop(ctx)
	needState := true
	for ctx.Err() == nil {
		if needState {
			if err := s.loadState(ctx); err != nil {
				s.setErr(err)
				if !sleep() {
					return
				}
				continue
			}
			needState = false
		}
		err := s.stream(ctx)
		s.setConnected(false)
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, errResync) {
			s.resyncs.Add(1)
			s.journal.Add("data", "", "Стан перечитано з alertd повністю (resync)")
			needState = true
			backoff = 200 * time.Millisecond
			continue
		}
		s.setErr(err)
		s.reconnects.Add(1)
		if !sleep() {
			return
		}
	}
}

func (s *Source) setErr(err error) {
	if err != nil {
		s.lastErr.Store(err.Error())
	}
}

func (s *Source) setConnected(v bool) {
	if s.connected.Swap(v) != v {
		s.connChanged.Store(time.Now().UnixMilli())
	}
}

func (s *Source) get(ctx context.Context, path string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", s.base+path, nil)
	resp, err := s.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("alertd %s: HTTP %d", path, resp.StatusCode)
	}
	s.lastContact.Store(time.Now().UnixMilli())
	return json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(out)
}

func (s *Source) loadRegions(ctx context.Context) error {
	var rs []Region
	if err := s.get(ctx, "/regions", &rs); err != nil {
		return err
	}
	if len(rs) == 0 {
		return errors.New("alertd: дерево регіонів ще порожнє")
	}
	old := s.state.Tree()
	t := BuildTree(withTestRegions(rs))
	if old.Len() > 0 && sameTree(old, t) {
		return nil
	}
	s.state.SetTree(t)
	s.hub.Reindex()
	logf("regions: %d", t.Len())
	return nil
}

func sameTree(a, b *Tree) bool {
	if a.Len() != b.Len() {
		return false
	}
	for id, r := range a.byID {
		if b.byID[id] != r {
			return false
		}
	}
	return true
}

func (s *Source) regionsLoop(ctx context.Context) {
	t := time.NewTicker(s.regionsEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.loadRegions(ctx); err != nil {
				logf("regions refresh: %v", err)
			}
		}
	}
}

type stateItem struct {
	RegionID  string  `json:"regionId"`
	AlarmType string  `json:"alarmType"`
	Since     jtime   `json:"since"`
	Active    []Level `json:"activeAlertLevels"`
}

func (s *Source) loadState(ctx context.Context) error {
	var st struct {
		API    int         `json:"api"`
		Epoch  string      `json:"epoch"`
		Seq    int64       `json:"seq"`
		Active []stateItem `json:"active"`
	}
	if err := s.get(ctx, "/state", &st); err != nil {
		return err
	}
	if st.API != 1 {
		return fmt.Errorf("alertd: непідтримувана версія API %d (потрібна 1)", st.API)
	}
	alerts := make([]*Alert, 0, len(st.Active))
	for _, it := range st.Active {
		if isTestRegion(it.RegionID) {
			continue
		}
		alerts = append(alerts, &Alert{Region: it.RegionID, Type: it.AlarmType, Levels: canon(it.Active), Since: it.Since.Time})
	}
	s.state.Replace(alerts)
	s.epoch, s.seq = st.Epoch, st.Seq
	s.epochV.Store(st.Epoch)
	s.everLoaded.Store(true)
	s.hub.NotifyAll()
	logf("state from alertd: %d active, seq=%d, epoch=%s", len(alerts), st.Seq, st.Epoch)
	return nil
}

func canon(ls []Level) []Level {
	out := make([]Level, 0, len(ls))
	for _, l := range ls {
		l.Level = strings.TrimSpace(l.Level)
		out = append(out, l)
	}
	return out
}

type alertdEvent struct {
	Seq         int64   `json:"seq"`
	RegionID    string  `json:"regionId"`
	AlarmType   string  `json:"alarmType"`
	Change      string  `json:"change"`
	Active      []Level `json:"activeAlertLevels"`
	SessionFrom jtime   `json:"sessionStartedAt"`
	CreatedAt   jtime   `json:"createdAt"`
	ReceivedAt  jtime   `json:"receivedAt"`
	Source      string  `json:"source"` // webhook | poll | startup
}

// stream читає /events, доки з'єднання живе. Watchdog рве з'єднання, якщо alertd мовчить
// довше за idleTimeout (alertd шле ping кожні 15 с).
func (s *Source) stream(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", s.base+"/events?after="+strconv.FormatInt(s.seq, 10), nil)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := s.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("alertd /events: HTTP %d", resp.StatusCode)
	}
	var alive atomic.Int64
	alive.Store(time.Now().UnixMilli())
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if time.Since(time.UnixMilli(alive.Load())) > s.idleTimeout {
					logf("alertd stream idle > %s, reconnecting", s.idleTimeout)
					cancel()
					return
				}
			}
		}
	}()
	rd := bufio.NewReaderSize(resp.Body, 64<<10)
	var evType, data, id string
	gotHello := false
	for {
		line, err := readLine(rd, 4<<20)
		if err != nil {
			return err
		}
		now := time.Now()
		alive.Store(now.UnixMilli())
		s.lastContact.Store(now.UnixMilli())
		if line != "" {
			switch {
			case strings.HasPrefix(line, ":"):
			case strings.HasPrefix(line, "event:"):
				evType = strings.TrimSpace(line[6:])
			case strings.HasPrefix(line, "data:"):
				data += strings.TrimPrefix(line[5:], " ")
			case strings.HasPrefix(line, "id:"):
				id = strings.TrimSpace(line[3:])
			}
			continue
		}
		// кінець події
		switch evType {
		case "hello":
			var h struct {
				API   int    `json:"api"`
				Epoch string `json:"epoch"`
			}
			if json.Unmarshal([]byte(data), &h) != nil || h.API != 1 {
				return fmt.Errorf("alertd: некоректний hello: %.200s", data)
			}
			if h.Epoch != s.epoch {
				logf("alertd epoch changed (%s → %s): full resync", s.epoch, h.Epoch)
				return errResync
			}
			gotHello = true
			s.setConnected(true)
		case "resync":
			return errResync
		case "alert":
			if !gotHello {
				return errors.New("alertd: подія до hello")
			}
			var ev alertdEvent
			if err := json.Unmarshal([]byte(data), &ev); err != nil {
				logf("alertd: bad event %s: %v", clean(data, 200), err)
				break
			}
			if n, err := strconv.ParseInt(id, 10, 64); err == nil && n > s.seq {
				s.seq = n
			} else if ev.Seq > s.seq {
				s.seq = ev.Seq
			}
			s.applyEvent(ev)
		}
		evType, data, id = "", "", ""
	}
}

func (s *Source) applyEvent(ev alertdEvent) {
	if isTestRegion(ev.RegionID) {
		return // тестову область alertd змінювати не може
	}
	ended := ev.Change == "end" || len(ev.Active) == 0
	a := &Alert{Region: ev.RegionID, Type: ev.AlarmType, Levels: canon(ev.Active), Since: ev.SessionFrom.Time}
	if st := s.state.Apply(a, ended); st != "" {
		s.applied.Add(1)
		now := time.Now()
		hook := ev.Source == "webhook" && !ev.CreatedAt.IsZero()
		s.state.markApplied(s.state.Version(), now, ev.CreatedAt.Time, hook)
		if s.metrics != nil {
			s.metrics.Event(ev.ReceivedAt.Sub(ev.CreatedAt.Time), hook && !ev.ReceivedAt.IsZero())
		}
		s.hub.Notify(st)
	}
}

// readLine — рядок без \n; довші за max — помилка (захист від нескінченного рядка).
func readLine(r *bufio.Reader, max int) (string, error) {
	var b []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			return "", err
		}
		b = append(b, chunk...)
		if len(b) > max {
			return "", errors.New("alertd: задовгий рядок у потоці")
		}
		if !isPrefix {
			return string(b), nil
		}
	}
}

// healthLoop — раз на 10 с бере з alertd час останньої звірки з API ukrainealarm.
func (s *Source) healthLoop(ctx context.Context) {
	t := time.NewTicker(s.healthEvery)
	defer t.Stop()
	for {
		var h struct {
			LastSync int64 `json:"lastSync"`
		}
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		req, _ := http.NewRequestWithContext(c, "GET", s.base+"/health", nil)
		if resp, err := s.hc.Do(req); err == nil {
			// 503 теж містить lastSync — він і потрібен
			if json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&h) == nil && h.LastSync > 0 {
				s.verifiedAt.Store(h.LastSync)
			}
			resp.Body.Close()
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// staleLoop — коли свіжість даних змінюється, потоки отримують подію meta.
func (s *Source) staleLoop(ctx context.Context) {
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			st, _ := s.Fresh(time.Now())
			if s.lastStale.Swap(st) != st {
				logf("data stale: %v", st)
				if st {
					s.journal.Add("data", "", "Дані застаріли: немає зв'язку з alertd або давно не було звірки з API")
				} else {
					s.journal.Add("data", "", "Дані знову свіжі")
				}
				s.hub.NotifyAll()
			}
		}
	}
}

// Fresh — чи можна довіряти даним. stale, якщо знімок ще не завантажено, потік з alertd
// розірваний довше за downGrace (20 с), або alertd давно (> STALE_AFTER) не звіряв стан з API.
// verified — коли стан востаннє підтверджено повним знімком ukrainealarm.
func (s *Source) Fresh(now time.Time) (stale bool, verified time.Time) {
	if v := s.verifiedAt.Load(); v > 0 {
		verified = time.Unix(v, 0)
	}
	if !s.everLoaded.Load() {
		return true, verified
	}
	if !s.connected.Load() && now.Sub(time.UnixMilli(s.connChanged.Load())) > s.downGrace {
		return true, verified
	}
	if verified.IsZero() || now.Sub(verified) > s.staleAfter {
		return true, verified
	}
	return false, verified
}

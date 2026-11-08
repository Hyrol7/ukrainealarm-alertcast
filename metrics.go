package main

import (
	"database/sql"
	"encoding/json"
	"sort"
	"sync"
	"time"
)

// Похвилинні метрики за 24 год (1440 хвилин): запити, потоки, затримки. Зберігаються в БД,
// тож графіки переживають перезапуск.

const metricsWindow = 1440 // хвилин

// Minute — одна хвилина. Затримки — у мілісекундах (медіана й p90 за хвилину).
type Minute struct {
	T        int64      `json:"t"` // unix-час початку хвилини (с)
	OK       int64      `json:"ok"`
	Unauth   int64      `json:"unauth"`
	Forbid   int64      `json:"forbid"`
	Limited  int64      `json:"limited"`
	Streams  int        `json:"streams"`
	Webhook  [2]float64 `json:"webhook"`  // ukrainealarm → alertd: p50, p90
	Delivery [2]float64 `json:"delivery"` // alertd → пристрій (наша частина)
	Full     [2]float64 `json:"full"`     // подія ukrainealarm → пристрій
	Events   int64      `json:"events"`   // змін від alertd
}

type TokenMinute struct {
	T       int64 `json:"t"`
	Req     int64 `json:"req"`
	Unauth  int64 `json:"unauth"`
	Forbid  int64 `json:"forbid"`
	Limited int64 `json:"limited"`
}

const maxSamples = 4000 // на хвилину на показник — обмеження пам'яті

type Metrics struct {
	mu      sync.Mutex
	dbMu    sync.Mutex // запис у БД — поза mu, щоб запити не чекали на диск
	cur     Minute
	webhook []float64
	deliv   []float64
	full    []float64
	hist    []Minute // завершені хвилини, від старіших
	tok     map[string]*TokenMinute
	tokHist map[string][]TokenMinute
	db      *sql.DB
	now     func() time.Time
}

const metricsSchema = `
CREATE TABLE IF NOT EXISTS metrics (t INTEGER PRIMARY KEY, data TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS token_metrics (t INTEGER NOT NULL, token TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (t, token)) WITHOUT ROWID;
`

func NewMetrics(db *sql.DB) (*Metrics, error) {
	m := &Metrics{tok: map[string]*TokenMinute{}, tokHist: map[string][]TokenMinute{}, db: db, now: time.Now}
	m.cur.T = m.now().Truncate(time.Minute).Unix()
	if db == nil {
		return m, nil
	}
	if _, err := db.Exec(metricsSchema); err != nil {
		return nil, err
	}
	since := m.cur.T - metricsWindow*60
	rows, err := db.Query(`SELECT data FROM metrics WHERE t >= ? ORDER BY t`, since)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var s string
		var mi Minute
		if rows.Scan(&s) == nil && json.Unmarshal([]byte(s), &mi) == nil {
			m.hist = append(m.hist, mi)
		}
	}
	rows.Close()
	rows, err = db.Query(`SELECT token, data FROM token_metrics WHERE t >= ? ORDER BY t`, since)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, s string
		var tm TokenMinute
		if rows.Scan(&id, &s) == nil && json.Unmarshal([]byte(s), &tm) == nil {
			m.tokHist[id] = append(m.tokHist[id], tm)
		}
	}
	rows.Close()
	return m, nil
}

func (m *Metrics) tokLocked(id string) *TokenMinute {
	t := m.tok[id]
	if t == nil {
		t = &TokenMinute{T: m.cur.T}
		m.tok[id] = t
	}
	return t
}

// Request — результат запиту: code 200/401/403/429; tokenID може бути "" (невідомий токен).
func (m *Metrics) Request(tokenID string, code int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rollLocked()
	var t *TokenMinute
	if tokenID != "" {
		t = m.tokLocked(tokenID)
	}
	switch code {
	case 401:
		m.cur.Unauth++
		if t != nil {
			t.Unauth++
		}
	case 403:
		m.cur.Forbid++
		if t != nil {
			t.Forbid++
		}
	case 429:
		m.cur.Limited++
		if t != nil {
			t.Limited++
		}
	default:
		m.cur.OK++
		if t != nil {
			t.Req++
		}
	}
}

func addSample(xs []float64, v float64) []float64 {
	if len(xs) < maxSamples {
		return append(xs, v)
	}
	return xs
}

// Event — зміна від alertd: webhook-затримка (лише для подій від webhook).
func (m *Metrics) Event(webhookLag time.Duration, fromWebhook bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rollLocked()
	m.cur.Events++
	if fromWebhook && webhookLag >= 0 && webhookLag < time.Hour {
		m.webhook = addSample(m.webhook, float64(webhookLag.Milliseconds()))
	}
}

// Delivered — подію відправлено в потік: наша доставка і (для webhook) повний шлях.
func (m *Metrics) Delivered(delivery, full time.Duration, hasFull bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rollLocked()
	if delivery >= 0 && delivery < time.Hour {
		m.deliv = addSample(m.deliv, float64(delivery.Microseconds())/1000)
	}
	if hasFull && full >= 0 && full < time.Hour {
		m.full = addSample(m.full, float64(full.Milliseconds()))
	}
}

func pct(xs []float64) [2]float64 {
	if len(xs) == 0 {
		return [2]float64{-1, -1}
	}
	sort.Float64s(xs)
	at := func(p float64) float64 { return xs[int(p*float64(len(xs)-1))] }
	return [2]float64{at(0.5), at(0.9)}
}

// rollLocked — хвилина минула: закрити її, записати, почати нову.
func (m *Metrics) rollLocked() {
	now := m.now().Truncate(time.Minute).Unix()
	if now == m.cur.T {
		return
	}
	m.closeLocked(now)
	m.cur = Minute{T: now}
	m.webhook, m.deliv, m.full = nil, nil, nil
	m.tok = map[string]*TokenMinute{}
}

// closeLocked — закрити поточну хвилину; now — початок нової (вікно 24 год рахується від неї,
// тож після довгої перерви старе відкидається одразу).
func (m *Metrics) closeLocked(now int64) {
	c := m.cur
	c.Webhook, c.Delivery, c.Full = pct(m.webhook), pct(m.deliv), pct(m.full)
	m.hist = append(m.hist, c)
	cut := now - metricsWindow*60
	for len(m.hist) > 0 && m.hist[0].T <= cut {
		m.hist = m.hist[1:]
	}
	toks := make(map[string]TokenMinute, len(m.tok))
	for id, t := range m.tok {
		toks[id] = *t
	}
	if m.db != nil {
		m.dbMu.Lock() // порядок записів зберігається: наступна хвилина чекає на цю
		go func() {
			defer m.dbMu.Unlock()
			m.persist(c, toks, cut)
		}()
	}
	for id, t := range m.tok {
		h := append(m.tokHist[id], *t)
		for len(h) > 0 && h[0].T <= cut {
			h = h[1:]
		}
		m.tokHist[id] = h
	}
	for id, h := range m.tokHist {
		for len(h) > 0 && h[0].T <= cut {
			h = h[1:]
		}
		if len(h) == 0 {
			delete(m.tokHist, id)
		} else {
			m.tokHist[id] = h
		}
	}
}

// persist — запис закритої хвилини (в одній транзакції) і чистка старшого за 24 год.
func (m *Metrics) persist(c Minute, toks map[string]TokenMinute, cut int64) {
	tx, err := m.db.Begin()
	if err != nil {
		return
	}
	b, _ := json.Marshal(c)
	_, _ = tx.Exec(`INSERT OR REPLACE INTO metrics(t, data) VALUES (?, ?)`, c.T, string(b))
	for id, t := range toks {
		b, _ := json.Marshal(t)
		_, _ = tx.Exec(`INSERT OR REPLACE INTO token_metrics(t, token, data) VALUES (?, ?, ?)`, t.T, id, string(b))
	}
	_, _ = tx.Exec(`DELETE FROM metrics WHERE t <= ?`, cut)
	_, _ = tx.Exec(`DELETE FROM token_metrics WHERE t <= ?`, cut)
	_ = tx.Commit()
}

// Wait — дочекатися запису в БД (тести, зупинка служби).
func (m *Metrics) Wait() { m.dbMu.Lock(); m.dbMu.Unlock() }

// Tick — раз на хвилину (і перед читанням): знімок кількості потоків, закриття хвилини.
func (m *Metrics) Tick(streams int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rollLocked()
	m.cur.Streams = streams
}

// History — завершені хвилини за 24 год.
func (m *Metrics) History() []Minute {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rollLocked()
	return append([]Minute{}, m.hist...)
}

func (m *Metrics) TokenHistory(id string) []TokenMinute {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rollLocked()
	out := append([]TokenMinute{}, m.tokHist[id]...)
	if t := m.tok[id]; t != nil {
		out = append(out, *t)
	}
	return out
}

// Sums24h — підсумки за 24 год (для таблиці токенів).
func (m *Metrics) TokenSums() map[string]TokenMinute {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rollLocked()
	out := map[string]TokenMinute{}
	add := func(id string, t TokenMinute) {
		s := out[id]
		s.Req += t.Req
		s.Unauth += t.Unauth
		s.Forbid += t.Forbid
		s.Limited += t.Limited
		out[id] = s
	}
	for id, h := range m.tokHist {
		for _, t := range h {
			add(id, t)
		}
	}
	for id, t := range m.tok {
		add(id, *t)
	}
	return out
}

// Totals — підсумки за 24 год і поточна хвилина (для плиток моніторингу).
func (m *Metrics) Totals() (sum Minute, lastMin Minute) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rollLocked()
	for _, h := range m.hist {
		sum.OK += h.OK
		sum.Unauth += h.Unauth
		sum.Forbid += h.Forbid
		sum.Limited += h.Limited
		sum.Events += h.Events
	}
	sum.OK += m.cur.OK
	sum.Unauth += m.cur.Unauth
	sum.Forbid += m.cur.Forbid
	sum.Limited += m.cur.Limited
	if len(m.hist) > 0 {
		lastMin = m.hist[len(m.hist)-1]
	}
	return sum, lastMin
}

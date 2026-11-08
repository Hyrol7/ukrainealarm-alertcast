package main

import (
	"database/sql"
	"fmt"
	"sync"
	"time"
)

// Журнал подій для адмінки: входи, зміни токенів, блокування, зв'язок з alertd, свіжість
// даних, тестова область, старт і зупинка служби. Зберігається 30 днів; останні — у пам'яті.

const (
	journalKeep = 30 * 24 * time.Hour
	journalMem  = 500
)

type JournalEntry struct {
	T    time.Time `json:"t"`
	Kind string    `json:"kind"` // login | token | ban | service | data | test
	Text string    `json:"text"`
	IP   string    `json:"ip,omitempty"`
}

type Journal struct {
	mu  sync.Mutex
	mem []JournalEntry
	db  *sql.DB
}

func NewJournal(db *sql.DB) (*Journal, error) {
	j := &Journal{db: db}
	if db == nil {
		return j, nil
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS journal (t_ms INTEGER NOT NULL, kind TEXT NOT NULL, text TEXT NOT NULL, ip TEXT NOT NULL DEFAULT '')`); err != nil {
		return nil, err
	}
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS journal_t ON journal(t_ms)`)
	rows, err := db.Query(`SELECT t_ms, kind, text, ip FROM (SELECT * FROM journal ORDER BY t_ms DESC LIMIT ?) ORDER BY t_ms`, journalMem)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var e JournalEntry
		var ms int64
		if rows.Scan(&ms, &e.Kind, &e.Text, &e.IP) == nil {
			e.T = time.UnixMilli(ms)
			j.mem = append(j.mem, e)
		}
	}
	return j, nil
}

// Add — запис у журнал (і в журнал systemd).
func (j *Journal) Add(kind, ip, format string, args ...any) {
	if j == nil {
		return
	}
	e := JournalEntry{T: time.Now(), Kind: kind, Text: clean(fmt.Sprintf(format, args...), 300), IP: clean(ip, 64)}
	j.mu.Lock()
	j.mem = append(j.mem, e)
	if len(j.mem) > journalMem {
		j.mem = j.mem[len(j.mem)-journalMem:]
	}
	j.mu.Unlock()
	if j.db != nil {
		_, _ = j.db.Exec(`INSERT INTO journal(t_ms, kind, text, ip) VALUES (?, ?, ?, ?)`, e.T.UnixMilli(), e.Kind, e.Text, e.IP)
	}
}

// Recent — останні записи, новіші першими; kind "" — усі.
func (j *Journal) Recent(limit int, kind string) []JournalEntry {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]JournalEntry, 0, limit)
	for i := len(j.mem) - 1; i >= 0 && len(out) < limit; i-- {
		if kind == "" || j.mem[i].Kind == kind {
			out = append(out, j.mem[i])
		}
	}
	return out
}

// humanDur — тривалість для людей: «15 хв», «1 год 30 хв», «45 с».
func humanDur(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d с", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d хв", int(d.Minutes()))
	case d%time.Hour == 0:
		return fmt.Sprintf("%d год", int(d.Hours()))
	}
	return fmt.Sprintf("%d год %d хв", int(d.Hours()), int(d.Minutes())%60)
}

func (j *Journal) Prune(now time.Time) {
	if j.db != nil {
		_, _ = j.db.Exec(`DELETE FROM journal WHERE t_ms < ?`, now.Add(-journalKeep).UnixMilli())
	}
}

package main

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Тестова область: вигадані регіони, тривогами в яких керує адміністратор (адмінка або
// `alertcast testregion`). Стан рахується тим самим кодом, що й для справжніх, але:
//   - бачать її лише токени, яким вона дозволена ЯВНО («усі регіони» її не включають);
//   - кожен стан позначено "test": true;
//   - у сумісному v3, на публічній сторінці й у даних alertd її немає;
//   - alertd не може її змінити (події з такими ID ігноруються);
//   - тривога без змін довше за testTTL знімається сама.

const (
	testRoot = "990000"
	testTTL  = time.Hour
)

var testRegions = []Region{
	{ID: "990000", Name: "Тестова область", Type: "State", StateID: "990000"},
	{ID: "990100", Name: "Тестовий район 1", Type: "District", ParentID: "990000", StateID: "990000", Depth: 1},
	{ID: "990101", Name: "Тестова громада 1.1", Type: "Community", ParentID: "990100", StateID: "990000", Depth: 2},
	{ID: "990102", Name: "Тестова громада 1.2", Type: "Community", ParentID: "990100", StateID: "990000", Depth: 2},
	{ID: "990200", Name: "Тестовий район 2", Type: "District", ParentID: "990000", StateID: "990000", Depth: 1},
}

var testIDs = func() map[string]bool {
	m := map[string]bool{}
	for _, r := range testRegions {
		m[r.ID] = true
	}
	return m
}()

func isTestRegion(id string) bool { return testIDs[id] }

// withTestRegions — справжнє дерево плюс тестова область (якщо справжнє дерево не зайняло
// ці ID — тоді тестова область вимикається, справжні дані важливіші).
func withTestRegions(rs []Region) []Region {
	for _, r := range rs {
		if testIDs[r.ID] {
			logf("test region disabled: real region %s uses a reserved ID", r.ID)
			return rs
		}
	}
	return append(append([]Region(nil), rs...), testRegions...)
}

var testTypesAllowed = []string{"AIR", "ARTILLERY", "URBAN_FIGHTS", "CHEMICAL", "NUCLEAR"}

// SetTestAlert — оголосити (red, yellow, unknown) чи зняти (none) тестову тривогу.
func (s *State) SetTestAlert(region, typ, level string, now time.Time) error {
	if !isTestRegion(region) {
		return fmt.Errorf("регіон %s не належить до тестової області (990000…)", region)
	}
	if _, ok := s.Tree().Get(region); !ok {
		return errors.New("тестова область вимкнена")
	}
	typ = strings.ToUpper(strings.TrimSpace(typ))
	if typ == "" {
		typ = "AIR"
	}
	okType := false
	for _, t := range testTypesAllowed {
		okType = okType || t == typ
	}
	if !okType {
		return fmt.Errorf("тип: %s", strings.Join(testTypesAllowed, ", "))
	}
	level = strings.ToLower(strings.TrimSpace(level))
	if level == "none" {
		s.Apply(&Alert{Region: region, Type: typ}, true)
		return nil
	}
	name, ok := map[string]string{"red": "Red", "yellow": "Yellow", "unknown": ""}[level]
	if !ok {
		return errors.New("рівень: red, yellow, unknown або none")
	}
	since := now
	for _, x := range s.byRegionSnapshot(region) {
		if x.Type == typ {
			since = x.Since // тривога триває — початок той самий
		}
	}
	s.Apply(&Alert{Region: region, Type: typ, Since: since, Levels: []Level{{Level: name, CreatedAt: jtime{now}}}}, false)
	return nil
}

// ClearTest — зняти всі тестові тривоги; olderThan>0 — лише без змін довше за цей час.
func (s *State) ClearTest(now time.Time, olderThan time.Duration) int {
	var drop []*Alert
	s.mu.RLock()
	for id, as := range s.byRegion {
		if !isTestRegion(id) {
			continue
		}
		for _, a := range as {
			if olderThan == 0 || now.Sub(a.lastUpdate()) > olderThan {
				drop = append(drop, a)
			}
		}
	}
	s.mu.RUnlock()
	for _, a := range drop {
		s.Apply(&Alert{Region: a.Region, Type: a.Type}, true)
	}
	return len(drop)
}

// TestAlert — тестова тривога для показу в адмінці.
type TestAlert struct {
	Region  string    `json:"region"`
	Type    string    `json:"type"`
	Level   string    `json:"level"`
	Since   time.Time `json:"since"`
	Changed time.Time `json:"changed"`
}

func (s *State) TestAlerts() []TestAlert {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []TestAlert
	for id, as := range s.byRegion {
		if !isTestRegion(id) {
			continue
		}
		for _, a := range as {
			lv := "unknown"
			if len(a.Levels) > 0 {
				lv = normLevel(a.Levels[0].Level)
			}
			out = append(out, TestAlert{Region: id, Type: a.Type, Level: lv, Since: a.Since, Changed: a.lastUpdate()})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Region != out[j].Region {
			return out[i].Region < out[j].Region
		}
		return out[i].Type < out[j].Type
	})
	return out
}

// byRegionSnapshot — копія власних тривог регіону.
func (s *State) byRegionSnapshot(id string) []*Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]*Alert(nil), s.byRegion[id]...)
}

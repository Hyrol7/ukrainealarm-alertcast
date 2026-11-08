package main

import (
	"sort"
)

// Сумісність з ukrainealarm API v3: ті самі поля й семантика, що й в оригіналу.
// Запис регіону в /alerts містить тривоги, оголошені для самого регіону, його предків і
// вкладених регіонів (так ukrainealarm повторює районну тривогу в записах області, району
// й кожної громади); кожна тривога — зі своїм regionId.

type v3Alert struct {
	RegionID   string  `json:"regionId"`
	RegionType string  `json:"regionType"`
	Type       string  `json:"type"`
	LastUpdate jtime   `json:"lastUpdate"`
	Levels     []Level `json:"activeAlertLevels"`
}

type v3Record struct {
	RegionID     string    `json:"regionId"`
	RegionType   string    `json:"regionType"`
	RegionName   string    `json:"regionName"`
	LastUpdate   jtime     `json:"lastUpdate"`
	ActiveAlerts []v3Alert `json:"activeAlerts"`
}

type v3Region struct {
	RegionID   string     `json:"regionId"`
	RegionName string     `json:"regionName"`
	RegionType string     `json:"regionType"`
	Children   []v3Region `json:"regionChildIds"`
}

type compatCache struct {
	version uint64
	valid   bool
	records []v3Record // відсортовані за regionId
}

func (s *State) v3AlertLocked(a *Alert) v3Alert {
	r := s.tree.byID[a.Region]
	lv := a.Levels
	if lv == nil {
		lv = []Level{}
	}
	return v3Alert{RegionID: a.Region, RegionType: r.Type, Type: a.Type, LastUpdate: jtime{a.lastUpdate()}, Levels: lv}
}

// recordLocked — запис v3 для регіону; ok=false, якщо пов'язаних тривог немає.
func (s *State) recordLocked(id string) (v3Record, bool) {
	r := s.tree.byID[id]
	rec := v3Record{RegionID: id, RegionType: r.Type, RegionName: r.Name, ActiveAlerts: []v3Alert{}}
	add := func(a *Alert) {
		va := s.v3AlertLocked(a)
		rec.ActiveAlerts = append(rec.ActiveAlerts, va)
		if va.LastUpdate.After(rec.LastUpdate.Time) {
			rec.LastUpdate = va.LastUpdate
		}
	}
	for _, c := range s.tree.chain(id) {
		for _, a := range s.byRegion[c] {
			add(a)
		}
	}
	for _, a := range s.byState[s.tree.stateOf(id)] {
		if a.Region != id && s.tree.Within(a.Region, id) {
			add(a)
		}
	}
	sort.Slice(rec.ActiveAlerts, func(i, j int) bool {
		x, y := rec.ActiveAlerts[i], rec.ActiveAlerts[j]
		if x.RegionID != y.RegionID {
			return x.RegionID < y.RegionID
		}
		return x.Type < y.Type
	})
	return rec, len(rec.ActiveAlerts) > 0
}

// V3Record — запис для одного регіону (порожній список тривог, якщо їх немає).
func (s *State) V3Record(id string) v3Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, _ := s.recordLocked(id)
	return rec
}

// V3All — записи всіх регіонів, яких стосується хоч одна тривога. Кешується до наступної зміни.
func (s *State) V3All() []v3Record {
	s.mu.RLock()
	if s.compat.valid && s.compat.version == s.version {
		out := s.compat.records
		s.mu.RUnlock()
		return out
	}
	ver := s.version
	ids := map[string]bool{}
	for id, as := range s.byRegion {
		if len(as) == 0 || isTestRegion(id) { // тестової області у v3 немає
			continue
		}
		for _, c := range s.tree.chain(id) { // сам регіон і предки
			ids[c] = true
		}
	}
	// вкладені регіони тих, де оголошено тривогу
	for id := range s.tree.byID {
		if ids[id] || isTestRegion(id) {
			continue
		}
		for _, c := range s.tree.chain(id)[1:] {
			if len(s.byRegion[c]) > 0 {
				ids[id] = true
				break
			}
		}
	}
	recs := make([]v3Record, 0, len(ids))
	for id := range ids {
		if rec, ok := s.recordLocked(id); ok {
			recs = append(recs, rec)
		}
	}
	s.mu.RUnlock()
	sort.Slice(recs, func(i, j int) bool { return idLess(recs[i].RegionID, recs[j].RegionID) })
	s.mu.Lock()
	if s.version == ver {
		s.compat = compatCache{version: ver, valid: true, records: recs}
	}
	s.mu.Unlock()
	return recs
}

func idLess(a, b string) bool {
	if len(a) != len(b) {
		return len(a) < len(b)
	}
	return a < b
}

// V3Regions — дерево у форматі ukrainealarm /api/v3/regions.
func (t *Tree) V3Regions() []v3Region {
	var build func(id string, depth int) v3Region
	build = func(id string, depth int) v3Region {
		r := t.byID[id]
		out := v3Region{RegionID: id, RegionName: r.Name, RegionType: r.Type, Children: []v3Region{}}
		if depth < maxDepth {
			for _, c := range t.children[id] {
				out.Children = append(out.Children, build(c, depth+1))
			}
		}
		return out
	}
	out := make([]v3Region, 0, len(t.roots))
	for _, id := range t.roots {
		if isTestRegion(id) {
			continue
		}
		out = append(out, build(id, 0))
	}
	return out
}

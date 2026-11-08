package main

import (
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"
)

// Region — вузол дерева регіонів ukrainealarm (як його віддає alertd /regions).
type Region struct {
	ID       string `json:"regionId"`
	Name     string `json:"regionName"`
	Type     string `json:"regionType"`
	ParentID string `json:"parentId,omitempty"`
	StateID  string `json:"stateId,omitempty"`
	Depth    int    `json:"depth"`
}

// jtime — час у JSON: RFC3339 (UTC), нульовий — null (як в alertd).
type jtime struct{ time.Time }

func (t jtime) MarshalJSON() ([]byte, error) {
	if t.IsZero() {
		return []byte("null"), nil
	}
	return json.Marshal(t.UTC().Format(time.RFC3339Nano))
}

func (t *jtime) UnmarshalJSON(b []byte) error {
	if string(b) == "null" || string(b) == `""` {
		t.Time = time.Time{}
		return nil
	}
	return json.Unmarshal(b, &t.Time)
}

// Level — рівень тривоги (як в alertd: Red — ракетна небезпека, Yellow — загроза БпЛА, Unknown).
type Level struct {
	Level     string `json:"alertLevel"`
	Reason    string `json:"reason"`
	CreatedAt jtime  `json:"createdAt"`
}

// Alert — тривога, оголошена саме для цього регіону й типу (сирий стан з alertd).
type Alert struct {
	Region string
	Type   string
	Levels []Level
	Since  time.Time
}

func (a *Alert) lastUpdate() time.Time {
	t := a.Since
	for _, l := range a.Levels {
		if l.CreatedAt.After(t) {
			t = l.CreatedAt.Time
		}
	}
	return t
}

const maxDepth = 8 // захист від циклів у дереві

// Tree — незмінне дерево регіонів.
type Tree struct {
	byID map[string]Region
	// children — прямі нащадки (для v3 /regions)
	children map[string][]string
	roots    []string
}

func BuildTree(rs []Region) *Tree {
	t := &Tree{byID: make(map[string]Region, len(rs)), children: map[string][]string{}}
	for _, r := range rs {
		if validID(r.ID) {
			t.byID[r.ID] = r
		}
	}
	for id, r := range t.byID {
		if _, ok := t.byID[r.ParentID]; ok && r.ParentID != id {
			t.children[r.ParentID] = append(t.children[r.ParentID], id)
		} else {
			t.roots = append(t.roots, id)
		}
	}
	byName := func(ids []string) {
		sort.Slice(ids, func(i, j int) bool {
			a, b := t.byID[ids[i]], t.byID[ids[j]]
			if a.Name != b.Name {
				return a.Name < b.Name
			}
			return ids[i] < ids[j]
		})
	}
	byName(t.roots)
	for _, c := range t.children {
		byName(c)
	}
	return t
}

func (t *Tree) Len() int { return len(t.byID) }

// All — усі регіони: області за назвою, під кожною — її нащадки (обхід у глибину).
func (t *Tree) All() []Region {
	out := make([]Region, 0, len(t.byID))
	var walk func(ids []string, depth int)
	walk = func(ids []string, depth int) {
		for _, id := range ids {
			r := t.byID[id]
			r.Depth = depth
			out = append(out, r)
			if depth < maxDepth {
				walk(t.children[id], depth+1)
			}
		}
	}
	walk(t.roots, 0)
	return out
}

func (t *Tree) Get(id string) (Region, bool) {
	r, ok := t.byID[id]
	return r, ok
}

// chain — сам регіон і всі його предки (до області), без циклів.
func (t *Tree) chain(id string) []string {
	out := make([]string, 0, 4)
	for cur, i := id, 0; cur != "" && i < maxDepth; i++ {
		out = append(out, cur)
		r, ok := t.byID[cur]
		if !ok || r.ParentID == "" || r.ParentID == cur {
			break
		}
		cur = r.ParentID
	}
	return out
}

// Within — id збігається з anc або лежить усередині нього.
func (t *Tree) Within(id, anc string) bool {
	for _, c := range t.chain(id) {
		if c == anc {
			return true
		}
	}
	return false
}

func (t *Tree) stateOf(id string) string {
	c := t.chain(id)
	if r, ok := t.byID[id]; ok && r.StateID != "" {
		return r.StateID
	}
	return c[len(c)-1]
}

func validID(s string) bool {
	if s == "" || len(s) > 16 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// ---------- обчислений стан ----------

// TypeStatus — стан регіону для одного типу тривоги.
type TypeStatus struct {
	State   string     `json:"state"`             // active | partial
	Levels  []string   `json:"levels"`            // red, yellow, unknown — від найвищого
	Since   *time.Time `json:"since,omitempty"`   // active: найраніший початок серед чинних тривог
	From    []string   `json:"from,omitempty"`    // active: де оголошено (сам регіон або його предки)
	Partial []string   `json:"partial,omitempty"` // partial: вкладені регіони з тривогою
}

// RegionStatus — стан регіону з урахуванням ієрархії.
type RegionStatus struct {
	ID    string                `json:"id"`
	Name  string                `json:"name,omitempty"`
	Type  string                `json:"type,omitempty"`
	Test  bool                  `json:"test,omitempty"`  // тестова область: тривоги вигадані
	State string                `json:"state"`           // none | partial | active
	Level string                `json:"level,omitempty"` // найвищий рівень серед типів у цьому стані
	Since *time.Time            `json:"since,omitempty"`
	Types map[string]TypeStatus `json:"types"`
}

var levelRank = map[string]int{"red": 3, "yellow": 2, "unknown": 1}

func normLevel(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "red":
		return "red"
	case "yellow":
		return "yellow"
	default:
		return "unknown"
	}
}

func addLevels(set map[string]bool, ls []Level) {
	if len(ls) == 0 {
		set["unknown"] = true
	}
	for _, l := range ls {
		set[normLevel(l.Level)] = true
	}
}

func sortedLevels(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for l := range set {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return levelRank[out[i]] > levelRank[out[j]] })
	return out
}

// State — сирий стан тривог і дерево. Читачі обчислюють стан регіонів під RLock.
type State struct {
	mu       sync.RWMutex
	tree     *Tree
	byRegion map[string][]*Alert  // регіон → його власні тривоги (усі типи)
	byState  map[string][]*Alert  // область → тривоги в ній (для «частково»)
	version  uint64               // зростає з кожною зміною (lastActionIndex для v3)
	applied  map[uint64]applyInfo // версія → коли застосовано (для вимірювання доставки)
	compat   compatCache
}

func NewState() *State {
	return &State{tree: BuildTree(nil), byRegion: map[string][]*Alert{}, byState: map[string][]*Alert{}}
}

func (s *State) Version() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.version
}

func (s *State) Tree() *Tree {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tree
}

// SetTree замінює дерево й перебудовує індекси областей. Повертає змінені області (усі).
func (s *State) SetTree(t *Tree) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tree = t
	s.reindexLocked()
	s.version++
}

// Replace замінює весь сирий стан (знімок /state з alertd).
func (s *State) Replace(alerts []*Alert) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.byRegion
	s.byRegion = map[string][]*Alert{}
	for id, as := range old { // тестова область — не з alertd, знімок її не стирає
		if isTestRegion(id) {
			s.byRegion[id] = as
		}
	}
	for _, a := range alerts {
		if validID(a.Region) && a.Type != "" {
			s.putLocked(a)
		}
	}
	s.reindexLocked()
	s.version++
}

// Apply застосовує одну зміну: nil-рівні або порожні — тривогу знято.
// Повертає область, якої стосується зміна ("" — нічого не змінилось).
func (s *State) Apply(a *Alert, ended bool) string {
	if !validID(a.Region) || a.Type == "" {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.byRegion[a.Region]
	idx := -1
	for i, x := range cur {
		if x.Type == a.Type {
			idx = i
		}
	}
	if ended {
		if idx < 0 {
			return ""
		}
		cur = append(cur[:idx:idx], cur[idx+1:]...)
		if len(cur) == 0 {
			delete(s.byRegion, a.Region)
		} else {
			s.byRegion[a.Region] = cur
		}
	} else if idx >= 0 {
		nc := append([]*Alert(nil), cur...)
		nc[idx] = a
		s.byRegion[a.Region] = nc
	} else {
		s.putLocked(a)
	}
	st := s.tree.stateOf(a.Region)
	s.reindexStateLocked(st)
	s.version++
	return st
}

func (s *State) putLocked(a *Alert) {
	cur := s.byRegion[a.Region]
	for i, x := range cur {
		if x.Type == a.Type {
			nc := append([]*Alert(nil), cur...)
			nc[i] = a
			s.byRegion[a.Region] = nc
			return
		}
	}
	s.byRegion[a.Region] = append(append([]*Alert(nil), cur...), a)
}

func (s *State) reindexLocked() {
	s.byState = map[string][]*Alert{}
	for id, as := range s.byRegion {
		st := s.tree.stateOf(id)
		s.byState[st] = append(s.byState[st], as...)
	}
}

func (s *State) reindexStateLocked(st string) {
	var out []*Alert
	for id, as := range s.byRegion {
		if s.tree.stateOf(id) == st {
			out = append(out, as...)
		}
	}
	if len(out) == 0 {
		delete(s.byState, st)
	} else {
		s.byState[st] = out
	}
}

type applyInfo struct {
	at, created time.Time
	webhook     bool
}

// markApplied — час застосування версії (кільце останніх 4096).
func (s *State) markApplied(ver uint64, at, created time.Time, webhook bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.applied == nil {
		s.applied = map[uint64]applyInfo{}
	}
	s.applied[ver] = applyInfo{at, created, webhook}
	if ver > 4096 {
		delete(s.applied, ver-4096)
	}
}

func (s *State) appliedInfo(ver uint64) (applyInfo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	i, ok := s.applied[ver]
	return i, ok
}

// ActiveCount — скільки (регіон, тип) мають власну тривогу.
func (s *State) ActiveCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for id, as := range s.byRegion {
		if !isTestRegion(id) {
			n += len(as)
		}
	}
	return n
}

// StateOf — область регіону (для підписок).
func (s *State) StateOf(id string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tree.stateOf(id)
}

// Status — стан регіону з ієрархією: active — тривога на сам регіон або на будь-якого
// предка; partial — тривоги лише у вкладених регіонах; none — нічого.
func (s *State) Status(id string) RegionStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.statusLocked(id)
}

func (s *State) statusLocked(id string) RegionStatus {
	rs := RegionStatus{ID: id, State: "none", Types: map[string]TypeStatus{}, Test: isTestRegion(id)}
	if r, ok := s.tree.byID[id]; ok {
		rs.Name, rs.Type = r.Name, r.Type
	}
	type acc struct {
		levels  map[string]bool
		since   time.Time
		from    []string
		partial []string
	}
	active, partial := map[string]*acc{}, map[string]*acc{}
	get := func(m map[string]*acc, t string) *acc {
		a := m[t]
		if a == nil {
			a = &acc{levels: map[string]bool{}}
			m[t] = a
		}
		return a
	}
	chain := s.tree.chain(id)
	for _, c := range chain {
		for _, al := range s.byRegion[c] {
			a := get(active, al.Type)
			addLevels(a.levels, al.Levels)
			if a.since.IsZero() || (!al.Since.IsZero() && al.Since.Before(a.since)) {
				a.since = al.Since
			}
			a.from = append(a.from, c)
		}
	}
	for _, al := range s.byState[s.tree.stateOf(id)] {
		if al.Region == id || active[al.Type] != nil || !s.tree.Within(al.Region, id) {
			continue
		}
		a := get(partial, al.Type)
		addLevels(a.levels, al.Levels)
		a.partial = append(a.partial, al.Region)
	}
	top := map[string]bool{}
	var since time.Time
	for t, a := range active {
		ts := TypeStatus{State: "active", Levels: sortedLevels(a.levels), From: a.from}
		if !a.since.IsZero() {
			v := a.since
			ts.Since = &v
			if since.IsZero() || v.Before(since) {
				since = v
			}
		}
		rs.Types[t] = ts
		for l := range a.levels {
			top[l] = true
		}
	}
	if len(active) > 0 {
		rs.State = "active"
		if !since.IsZero() {
			rs.Since = &since
		}
	}
	for t, a := range partial {
		sort.Strings(a.partial)
		rs.Types[t] = TypeStatus{State: "partial", Levels: sortedLevels(a.levels), Partial: a.partial}
		if len(active) == 0 {
			for l := range a.levels {
				top[l] = true
			}
		}
	}
	if len(active) == 0 && len(partial) > 0 {
		rs.State = "partial"
	}
	if ls := sortedLevels(top); len(ls) > 0 {
		rs.Level = ls[0]
	}
	return rs
}

// statusKey — канонічне подання для порівняння (чи змінився обчислений стан).
func statusKey(rs RegionStatus) string {
	b, _ := json.Marshal(rs)
	return string(b)
}

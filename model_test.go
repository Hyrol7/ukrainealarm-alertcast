package main

import (
	"fmt"
	"math/rand/v2"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// Дерево для тестів: 2 області, у кожній 3 райони, у кожному 3 громади.
//
//	1 (State) → 10, 11, 12 (District) → 100..102, 110..112, 120..122 (Community)
//	2 (State) → 20, 21, 22 → 200..222
func sampleRegions() []Region {
	var rs []Region
	for _, o := range []int{1, 2} {
		os := fmt.Sprint(o)
		rs = append(rs, Region{ID: os, Name: "Область " + os, Type: "State", StateID: os})
		for d := 0; d < 3; d++ {
			ds := fmt.Sprint(o*10 + d)
			rs = append(rs, Region{ID: ds, Name: "Район " + ds, Type: "District", ParentID: os, StateID: os, Depth: 1})
			for c := 0; c < 3; c++ {
				cs := fmt.Sprint(o*100 + d*10 + c)
				rs = append(rs, Region{ID: cs, Name: "Громада " + cs, Type: "Community", ParentID: ds, StateID: os, Depth: 2})
			}
		}
	}
	return rs
}

var t0 = time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)

func lv(level string, min int) Level {
	return Level{Level: level, CreatedAt: jtime{t0.Add(time.Duration(min) * time.Minute)}}
}

func al(region, typ string, sinceMin int, levels ...Level) *Alert {
	return &Alert{Region: region, Type: typ, Since: t0.Add(time.Duration(sinceMin) * time.Minute), Levels: levels}
}

func newTestState(alerts ...*Alert) *State {
	s := NewState()
	s.SetTree(BuildTree(sampleRegions()))
	s.Replace(alerts)
	return s
}

func TestHierarchyStatus(t *testing.T) {
	s := newTestState(al("10", "AIR", 5, lv("Red", 5), lv("Yellow", 3)))
	cases := []struct {
		id, state, level string
		from, partial    []string
	}{
		{"10", "active", "red", []string{"10"}, nil},  // сам район
		{"101", "active", "red", []string{"10"}, nil}, // громада в районі
		{"1", "partial", "red", nil, []string{"10"}},  // область — частково
		{"11", "none", "", nil, nil},                  // сусідній район
		{"110", "none", "", nil, nil},                 // громада сусіднього району
		{"2", "none", "", nil, nil},                   // інша область
		{"999", "none", "", nil, nil},                 // невідомий регіон
	}
	for _, c := range cases {
		st := s.Status(c.id)
		if st.State != c.state || st.Level != c.level {
			t.Errorf("%s: state=%s level=%s, want %s %s", c.id, st.State, st.Level, c.state, c.level)
		}
		if c.state == "none" {
			if len(st.Types) != 0 {
				t.Errorf("%s: types must be empty: %v", c.id, st.Types)
			}
			continue
		}
		air := st.Types["AIR"]
		if !reflect.DeepEqual(air.From, c.from) || !reflect.DeepEqual(air.Partial, c.partial) {
			t.Errorf("%s: from=%v partial=%v", c.id, air.From, air.Partial)
		}
		if !reflect.DeepEqual(air.Levels, []string{"red", "yellow"}) {
			t.Errorf("%s: levels %v", c.id, air.Levels)
		}
	}
	if st := s.Status("100"); st.Since == nil || !st.Since.Equal(t0.Add(5*time.Minute)) {
		t.Errorf("since: %v", st.Since)
	}
	if st := s.Status("1"); st.Since != nil || st.Types["AIR"].Since != nil {
		t.Errorf("partial must have no since: %+v", st)
	}
}

func TestOblastAlertCoversAll(t *testing.T) {
	s := newTestState(al("1", "AIR", 0, lv("Yellow", 0)), al("10", "AIR", 3, lv("Red", 3)))
	st := s.Status("101")
	if st.State != "active" || st.Level != "red" || !reflect.DeepEqual(st.Types["AIR"].From, []string{"10", "1"}) {
		t.Fatalf("community under oblast+district alerts: %+v", st)
	}
	if st.Since == nil || !st.Since.Equal(t0) {
		t.Fatalf("since must be the earliest (oblast): %v", st.Since)
	}
	if st := s.Status("1"); st.State != "active" || st.Level != "yellow" || len(st.Types["AIR"].Partial) != 0 {
		t.Fatalf("oblast itself: %+v", st)
	}
}

func TestTypesAreIndependent(t *testing.T) {
	s := newTestState(al("10", "AIR", 0, lv("Yellow", 0)), al("100", "ARTILLERY", 0))
	st := s.Status("10")
	if st.State != "active" || st.Types["AIR"].State != "active" || st.Types["ARTILLERY"].State != "partial" {
		t.Fatalf("mixed types: %+v", st.Types)
	}
	if st.Level != "yellow" { // рівень беруть лише з типів у верхньому стані (active)
		t.Fatalf("level from active types only: %s", st.Level)
	}
	if lv := st.Types["ARTILLERY"].Levels; !reflect.DeepEqual(lv, []string{"unknown"}) {
		t.Fatalf("alert without levels is unknown: %v", lv)
	}
}

func TestApplyStartUpdateEnd(t *testing.T) {
	s := newTestState()
	v0 := s.Version()
	if st := s.Apply(al("10", "AIR", 0, lv("Yellow", 0)), false); st != "1" {
		t.Fatalf("apply returned oblast %q", st)
	}
	if s.Status("100").Level != "yellow" {
		t.Fatal("start")
	}
	s.Apply(al("10", "AIR", 0, lv("Red", 1)), false)
	if st := s.Status("100"); st.Level != "red" || !reflect.DeepEqual(st.Types["AIR"].Levels, []string{"red"}) {
		t.Fatalf("update: %+v", st)
	}
	s.Apply(&Alert{Region: "10", Type: "AIR"}, true)
	if s.Status("100").State != "none" || s.ActiveCount() != 0 {
		t.Fatal("end")
	}
	if st := s.Apply(&Alert{Region: "10", Type: "AIR"}, true); st != "" {
		t.Fatal("ending a non-existent alert must be a no-op")
	}
	if s.Version() != v0+3 {
		t.Fatalf("version %d, want %d", s.Version(), v0+3)
	}
	for _, bad := range []*Alert{{Region: "x1", Type: "AIR"}, {Region: "", Type: "AIR"}, {Region: "10", Type: ""}} {
		if st := s.Apply(bad, false); st != "" {
			t.Fatalf("invalid alert applied: %+v", bad)
		}
	}
}

// Еталон: незалежна, навмисно «тупа» реалізація правил. Порівнюємо на випадкових станах.
func refStatus(tree *Tree, alerts []*Alert, id string) (state string, types map[string]string, levels map[string][]string) {
	types, levels = map[string]string{}, map[string][]string{}
	isAnc := func(anc, x string) bool { // anc — предок x або x сам
		for cur, i := x, 0; cur != "" && i < 10; i++ {
			if cur == anc {
				return true
			}
			r, ok := tree.byID[cur]
			if !ok {
				return false
			}
			cur = r.ParentID
		}
		return false
	}
	lset := map[string]map[string]bool{}
	for _, a := range alerts {
		if isAnc(a.Region, id) {
			if types[a.Type] != "active" {
				lset[a.Type] = map[string]bool{}
			}
			types[a.Type] = "active"
			for _, l := range a.Levels {
				lset[a.Type][normLevel(l.Level)] = true
			}
			if len(a.Levels) == 0 {
				lset[a.Type]["unknown"] = true
			}
		}
	}
	for _, a := range alerts {
		if a.Region != id && isAnc(id, a.Region) && types[a.Type] != "active" {
			types[a.Type] = "partial"
			if lset[a.Type] == nil {
				lset[a.Type] = map[string]bool{}
			}
			for _, l := range a.Levels {
				lset[a.Type][normLevel(l.Level)] = true
			}
			if len(a.Levels) == 0 {
				lset[a.Type]["unknown"] = true
			}
		}
	}
	state = "none"
	for _, v := range types {
		if v == "active" {
			state = "active"
		} else if state == "none" {
			state = "partial"
		}
	}
	for t, m := range lset {
		levels[t] = sortedLevels(m)
	}
	return
}

func TestStatusMatchesReference(t *testing.T) {
	tree := BuildTree(sampleRegions())
	ids := make([]string, 0, tree.Len())
	for id := range tree.byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rng := rand.New(rand.NewPCG(1, 2))
	typesAll := []string{"AIR", "ARTILLERY", "URBAN_FIGHTS"}
	levelsAll := []string{"Red", "Yellow", "", "weird"}
	for iter := 0; iter < 400; iter++ {
		var alerts []*Alert
		seen := map[string]bool{}
		for n := rng.IntN(8); n > 0; n-- {
			a := &Alert{Region: ids[rng.IntN(len(ids))], Type: typesAll[rng.IntN(len(typesAll))], Since: t0}
			if seen[a.Region+a.Type] {
				continue
			}
			seen[a.Region+a.Type] = true
			for k := rng.IntN(3); k > 0; k-- {
				a.Levels = append(a.Levels, Level{Level: levelsAll[rng.IntN(len(levelsAll))]})
			}
			alerts = append(alerts, a)
		}
		s := NewState()
		s.SetTree(tree)
		// половину ітерацій будуємо через Apply (з пошкодженням і відновленням), половину — Replace
		if iter%2 == 0 {
			s.Replace(alerts)
		} else {
			for _, a := range alerts {
				s.Apply(a, false)
			}
			if len(alerts) > 0 { // зняти й повернути одну тривогу — стан має відновитися
				x := alerts[rng.IntN(len(alerts))]
				s.Apply(&Alert{Region: x.Region, Type: x.Type}, true)
				s.Apply(x, false)
			}
		}
		for _, id := range ids {
			got := s.Status(id)
			wantState, wantTypes, wantLevels := refStatus(tree, alerts, id)
			if got.State != wantState || len(got.Types) != len(wantTypes) {
				t.Fatalf("iter %d region %s: got %s %v, want %s %v (alerts %s)", iter, id, got.State, got.Types, wantState, wantTypes, dump(alerts))
			}
			for typ, ws := range wantTypes {
				g := got.Types[typ]
				if g.State != ws || !reflect.DeepEqual(g.Levels, wantLevels[typ]) {
					t.Fatalf("iter %d region %s type %s: got %+v, want %s %v", iter, id, typ, g, ws, wantLevels[typ])
				}
			}
		}
	}
}

func dump(as []*Alert) string {
	var b strings.Builder
	for _, a := range as {
		fmt.Fprintf(&b, "%s/%s%v ", a.Region, a.Type, a.Levels)
	}
	return b.String()
}

// Пошкоджене дерево (цикл, сирота, сам собі батько) не вішає обчислення.
func TestTreeCyclesAndOrphans(t *testing.T) {
	rs := []Region{
		{ID: "1", ParentID: "2"}, {ID: "2", ParentID: "1"}, // цикл
		{ID: "3", ParentID: "3"},  // сам собі батько
		{ID: "4", ParentID: "99"}, // сирота
		{ID: "x", ParentID: "1"},  // некоректний ID — відкидається
	}
	tr := BuildTree(rs)
	if tr.Len() != 4 {
		t.Fatalf("len %d", tr.Len())
	}
	s := NewState()
	s.SetTree(tr)
	s.Replace([]*Alert{al("1", "AIR", 0), al("3", "AIR", 0), al("4", "AIR", 0)})
	for _, id := range []string{"1", "2", "3", "4"} {
		if st := s.Status(id); st.State == "none" {
			t.Fatalf("%s: %+v", id, st)
		}
	}
	_ = tr.V3Regions()
	_ = s.V3All()
}

func TestV3Compat(t *testing.T) {
	s := newTestState(al("10", "AIR", 0, lv("Red", 2)))
	all := s.V3All()
	got := map[string]int{}
	for _, r := range all {
		got[r.RegionID] = len(r.ActiveAlerts)
		for _, a := range r.ActiveAlerts {
			if a.RegionID != "10" || a.Type != "AIR" || a.RegionType != "District" || !a.LastUpdate.Equal(t0.Add(2*time.Minute)) {
				t.Fatalf("alert in record %s: %+v", r.RegionID, a)
			}
		}
	}
	// як в ukrainealarm: запис області, самого району і кожної його громади
	want := map[string]int{"1": 1, "10": 1, "100": 1, "101": 1, "102": 1}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("records: %v, want %v", got, want)
	}
	if ids := []string{all[0].RegionID, all[1].RegionID}; ids[0] != "1" || ids[1] != "10" {
		t.Fatalf("sorted numerically: %v", ids)
	}
	// кеш скидається зі зміною
	s.Apply(&Alert{Region: "10", Type: "AIR"}, true)
	if n := len(s.V3All()); n != 0 {
		t.Fatalf("cache not invalidated: %d", n)
	}
	if rec := s.V3Record("100"); rec.RegionName != "Громада 100" || len(rec.ActiveAlerts) != 0 || rec.ActiveAlerts == nil {
		t.Fatalf("empty record: %+v", rec)
	}
	reg := BuildTree(sampleRegions()).V3Regions()
	if len(reg) != 2 || len(reg[0].Children) != 3 || len(reg[0].Children[0].Children) != 3 {
		t.Fatalf("v3 regions shape: %+v", reg)
	}
}

func BenchmarkStatus(b *testing.B) {
	s := newTestState(al("1", "AIR", 0, lv("Red", 0)), al("21", "AIR", 0), al("222", "ARTILLERY", 0))
	for i := 0; i < b.N; i++ {
		s.Status("101")
		s.Status("2")
	}
}

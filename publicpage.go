package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
	_ "time/tzdata" // час на сторінці — київський, незалежно від налаштувань сервера
)

// Головна сторінка — таблиця поточних тривог (без тестової області). Рендериться
// на сервері й кешується до наступної зміни стану; скрипт раз на 15 с перепитує «/» з ETag
// і, якщо щось змінилось, підміняє таблицю.

//go:embed www/index.tmpl
var indexTmplSrc string

var indexTmpl = template.Must(template.New("index").Parse(indexTmplSrc))

var kyiv = func() *time.Location {
	if l, err := time.LoadLocation("Europe/Kyiv"); err == nil {
		return l
	}
	return time.FixedZone("EET", 2*3600)
}()

const indexScript = `(()=>{const d=document;let tag="";` +
	`async function t(){if(d.hidden)return;try{const r=await fetch("/",{cache:"no-store",headers:tag?{"If-None-Match":tag}:{}});` +
	`if(r.status===304)return;if(!r.ok)throw 0;tag=r.headers.get("ETag")||"";` +
	`const n=new DOMParser().parseFromString(await r.text(),"text/html").querySelector("main");` +
	`if(n)d.querySelector("main").replaceWith(n)}catch(e){const s=d.getElementById("st");if(s)s.textContent="немає зв'язку з сервером"}}` +
	`setInterval(t,15000);d.addEventListener("visibilitychange",t)})();`

var indexScriptHash = func() string {
	h := sha256.Sum256([]byte(indexScript))
	return "sha256-" + base64.StdEncoding.EncodeToString(h[:])
}()

type indexRow struct {
	Name, Kind, Level, Since string
	Top                      bool // рядок області
}

type indexData struct {
	Site, Status, Health string
	States, Districts    int
	Rows                 []indexRow
	Script               template.JS
}

var typeNames = map[string]string{"AIR": "повітряна", "ARTILLERY": "артобстріл", "URBAN_FIGHTS": "вуличні бої",
	"CHEMICAL": "хімічна", "NUCLEAR": "ядерна", "INFO": "інформація"}

var levelNames = map[string]string{"red": "ракети", "yellow": "БпЛА", "unknown": "не вказано"}

func levelText(ls []Level) string {
	set := map[string]bool{}
	for _, l := range ls {
		set[normLevel(l.Level)] = true
	}
	var out []string
	for _, k := range []string{"red", "yellow", "unknown"} {
		if set[k] {
			out = append(out, levelNames[k])
		}
	}
	if len(out) == 0 {
		return levelNames["unknown"]
	}
	return strings.Join(out, ", ")
}

func sinceText(t, now time.Time) string {
	if t.IsZero() {
		return ""
	}
	t, now = t.In(kyiv), now.In(kyiv)
	if t.YearDay() == now.YearDay() && t.Year() == now.Year() {
		return t.Format("15:04")
	}
	return t.Format("02.01 15:04")
}

// publicRows — таблиця: область (її тривоги або «частково»), під нею — райони й громади.
func (s *State) publicRows(now time.Time) (rows []indexRow, states, districts int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t := s.tree
	name := func(id string) string {
		if r, ok := t.byID[id]; ok && r.Name != "" {
			return r.Name
		}
		return "регіон " + id
	}
	ids := make([]string, 0, len(s.byState))
	for st := range s.byState {
		if !isTestRegion(st) && len(s.byState[st]) > 0 {
			ids = append(ids, st)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return name(ids[i]) < name(ids[j]) })
	alertRows := func(id string, top bool) []indexRow {
		as := append([]*Alert(nil), s.byRegion[id]...)
		sort.Slice(as, func(i, j int) bool { return as[i].Type < as[j].Type })
		var out []indexRow
		for _, a := range as {
			k := typeNames[a.Type]
			if k == "" {
				k = strings.ToLower(a.Type)
			}
			out = append(out, indexRow{Name: name(id), Kind: k, Level: levelText(a.Levels), Since: sinceText(a.Since, now), Top: top})
		}
		return out
	}
	for _, st := range ids {
		states++
		if len(s.byRegion[st]) > 0 {
			rows = append(rows, alertRows(st, true)...)
		} else {
			rows = append(rows, indexRow{Name: name(st), Kind: "частково", Top: true})
		}
		var subs []string
		seen := map[string]bool{}
		for _, a := range s.byState[st] {
			if a.Region != st && !seen[a.Region] {
				seen[a.Region] = true
				subs = append(subs, a.Region)
			}
		}
		sort.Slice(subs, func(i, j int) bool {
			ri, rj := t.byID[subs[i]], t.byID[subs[j]]
			if ri.Depth != rj.Depth {
				return ri.Depth < rj.Depth
			}
			return name(subs[i]) < name(subs[j])
		})
		for _, id := range subs {
			if r, ok := t.byID[id]; ok && r.Type == "District" {
				districts++
			}
			rows = append(rows, alertRows(id, false)...)
		}
	}
	return rows, states, districts
}

type indexCache struct {
	mu   sync.Mutex
	key  string
	body []byte
}

func (a *App) serveIndex(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	stale, _ := a.src.Fresh(now)
	h := a.health(now)
	key := fmt.Sprintf(`"%d-%s-%s-%d"`, a.state.Version(), h.Fresh, h.Link, now.Unix()/60)
	c := &a.index
	c.mu.Lock()
	if c.key != key {
		rows, st, ds := a.state.publicRows(now)
		d := indexData{Site: siteTitle, Rows: rows, States: st, Districts: ds, Script: template.JS(indexScript),
			Health: h.Overall, Status: "Оновлено " + now.In(kyiv).Format("15:04")}
		switch {
		case h.Fresh == "bad":
			d.Status += " · даних ще немає"
		case stale:
			d.Status += " · дані можуть бути застарілими"
		default:
			d.Status += " · дані свіжі"
		}
		var b bytes.Buffer
		if err := indexTmpl.Execute(&b, d); err != nil {
			c.mu.Unlock()
			errorPage(w, r, http.StatusInternalServerError)
			return
		}
		c.key, c.body = key, b.Bytes()
	}
	body := c.body
	c.mu.Unlock()
	if r.Header.Get("If-None-Match") == key {
		w.Header().Set("ETag", key)
		w.WriteHeader(http.StatusNotModified)
		return
	}
	pageHeaders(w.Header(), len(body))
	w.Header().Set("ETag", key)
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Security-Policy", cspBase+"; script-src '"+indexScriptHash+"'; connect-src 'self'")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		w.Write(body)
	}
}

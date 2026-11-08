package main

import (
	"bytes"
	_ "embed"
	"html/template"
	"net/http"
	"strconv"
	"time"
)

//go:embed www/page.tmpl
var pageTmplSrc string

var pageTmpl = template.Must(template.New("page").Funcs(template.FuncMap{"inc": func(i int) int { return i + 1 }}).Parse(pageTmplSrc))

type pageData struct {
	Code    int
	Label   string
	Dot     string
	Pulse   bool
	Pair    []string
	Title   string
	Text    string
	Refresh bool
	Script  template.JS
	Site    string
}

var siteTitle string

func SetSiteTitle(t string) {
	siteTitle = t
	renderedErrors = renderErrorPages()
}

// Тексти навмисно загальні: нічого не кажуть про сервіс.
var errorPages = map[int]pageData{
	http.StatusUnauthorized:          {Title: "Без доступу.", Text: "Цей запит не пройшов перевірку.", Dot: "warn"},
	http.StatusForbidden:             {Title: "Не для вас.", Text: "Доступу сюди немає.", Dot: "warn"},
	http.StatusNotFound:              {Title: "Тут нічого немає.", Text: "Такої сторінки не існує. Повертатися теж нікуди.", Dot: "warn"},
	http.StatusMethodNotAllowed:      {Title: "Не так.", Text: "Сюди так не звертаються.", Dot: "warn"},
	http.StatusRequestEntityTooLarge: {Title: "Забагато.", Text: "Запит завеликий для цієї адреси.", Dot: "warn"},
	http.StatusTooManyRequests:       {Title: "Повільніше.", Text: "Забагато запитів. Спробуйте трохи згодом.", Dot: "warn"},
	http.StatusInternalServerError:   {Title: "Щось зламалось.", Text: "Помилку записано. Її розберуть.", Dot: "bad"},
	http.StatusServiceUnavailable:    {Title: "Ще не готово.", Text: "Сервіс запускається. Спробуйте трохи згодом.", Dot: "warn"},
}

var renderedErrors = renderErrorPages()

func renderErrorPages() map[int][]byte {
	out := map[int][]byte{}
	for code, d := range errorPages {
		d.Code, d.Label, d.Site = code, strconv.Itoa(code), siteTitle
		var b bytes.Buffer
		if err := pageTmpl.Execute(&b, d); err != nil {
			panic(err)
		}
		out[code] = b.Bytes()
	}
	return out
}

const cspBase = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

func pageHeaders(h http.Header, n int) {
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("X-Robots-Tag", "noindex, nofollow")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", cspBase)
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Length", strconv.Itoa(n))
}

func writePage(w http.ResponseWriter, r *http.Request, code int, body []byte) {
	pageHeaders(w.Header(), len(body))
	w.WriteHeader(code)
	if r.Method != http.MethodHead {
		w.Write(body)
	}
}

func errorPage(w http.ResponseWriter, r *http.Request, code int) {
	b, ok := renderedErrors[code]
	if !ok {
		code, b = http.StatusInternalServerError, renderedErrors[http.StatusInternalServerError]
	}
	writePage(w, r, code, b)
}

// healthView — для індикатора: зв'язок з джерелом, свіжість даних, загалом.
type healthView struct{ Link, Fresh, Overall string }

// computeHealth — чиста функція (для тестів).
// Зв'язок: ok — потік з джерелом відкритий; warn — розірваний недавно (< 1 хв); bad — давніше.
// Свіжість: ok — дані підтверджено нещодавно; warn — дані застаріли; bad — даних ще немає.
func computeHealth(now time.Time, connected bool, connChanged time.Time, loaded, stale bool) healthView {
	var h healthView
	switch {
	case connected:
		h.Link = "ok"
	case now.Sub(connChanged) < time.Minute && !connChanged.IsZero():
		h.Link = "warn"
	default:
		h.Link = "bad"
	}
	switch {
	case !loaded:
		h.Fresh = "bad"
	case stale:
		h.Fresh = "warn"
	default:
		h.Fresh = "ok"
	}
	switch {
	case h.Link == "ok" && h.Fresh == "ok":
		h.Overall = "ok"
	case h.Fresh == "bad" || (h.Link == "bad" && h.Fresh != "ok"):
		h.Overall = "bad"
	default:
		h.Overall = "warn"
	}
	return h
}

var overallLabel = map[string]string{"ok": "online", "warn": "degraded", "bad": "offline"}

func (a *App) health(now time.Time) healthView {
	src := a.src
	stale, _ := src.Fresh(now)
	return computeHealth(now, src.connected.Load(), time.UnixMilli(src.connChanged.Load()), src.everLoaded.Load(), stale)
}

func (a *App) serveStatus(w http.ResponseWriter, r *http.Request) {
	h := a.health(time.Now())
	body := []byte(h.Overall + " " + h.Link + " " + h.Fresh + "\n")
	hd := w.Header()
	hd.Set("Content-Type", "text/plain; charset=utf-8")
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Cache-Control", "no-store")
	hd.Set("X-Robots-Tag", "noindex, nofollow")
	hd.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	hd.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		w.Write(body)
	}
}

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"time"
)

// /api/v1/events — стрічка змін окремих тривог (для ботів і власних баз): спершу знімок
// усіх чинних тривог у дозволених регіонах, далі — кожна зміна start | update | end.
// Ієрархію клієнт рахує сам (або бере /status); тут — сирі тривоги, як їх оголосили.
//
// Регіони — усі, що дозволені токену. Тестова область — лише якщо її дозволено токену явно
// або токен без обмежень регіонів і запит має ?test=1.

type eventsSnapshot struct {
	OK       bool        `json:"ok"`
	Stale    bool        `json:"stale"`
	Verified jtime       `json:"verifiedAt"`
	Version  uint64      `json:"version"`
	Alerts   []FeedEvent `json:"alerts"`
}

func (a *App) v1Events(w http.ResponseWriter, r *http.Request, tk *token, ip netip.Addr) {
	withTest := r.URL.Query().Get("test") == "1" && len(tk.Regions) == 0
	allow := func(tree *Tree) func(string) bool {
		return func(id string) bool {
			return tk.Allowed(tree, id) || (withTest && isTestRegion(id))
		}
	}
	sub := newSub(nil, tk.ID, ipKey(ip).String())
	sub.Listener = listenerName(r)
	switch a.hub.Add(sub, tk.Streams) {
	case "":
	case "token":
		apiError(w, r, http.StatusTooManyRequests, "too many streams for this token")
		return
	default:
		retryAfter(w, 30*time.Second)
		apiError(w, r, http.StatusServiceUnavailable, "too many streams")
		return
	}
	defer a.hub.Remove(sub)

	rc := http.NewResponseController(w)
	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	var buf bytes.Buffer
	flush := func() bool {
		_ = rc.SetWriteDeadline(time.Now().Add(15 * time.Second))
		if _, err := w.Write(buf.Bytes()); err != nil {
			return false
		}
		buf.Reset()
		return rc.Flush() == nil
	}
	// без «id:»: відновлення з місця обриву немає — після перепідключення приходить свіжий знімок
	event := func(name string, v any) {
		b, _ := json.Marshal(v)
		fmt.Fprintf(&buf, "event: %s\ndata: %s\n\n", name, b)
	}
	snapshot := func(name string) uint64 {
		alerts, ver, next := a.state.FeedSnapshot(allow(a.state.Tree()))
		stale, verified := a.src.Fresh(time.Now())
		event(name, eventsSnapshot{OK: true, Stale: stale, Verified: jtime{verified}, Version: ver, Alerts: alerts})
		return next
	}

	fmt.Fprintf(&buf, "retry: %d\n\n", 1000+rand.IntN(4000))
	cursor := snapshot("snapshot")
	lastStale, _ := a.src.Fresh(time.Now())
	if !flush() {
		return
	}
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	for {
		evs, lost, wake := a.state.feed.Since(cursor)
		if lost { // відстав більше, ніж вміщує буфер: новий знімок замість «дірявої» послідовності
			cursor = snapshot("resync")
			if !flush() {
				return
			}
			continue
		}
		if len(evs) > 0 {
			tree, sent := a.state.Tree(), 0
			ok := allow(tree)
			for _, e := range evs {
				cursor = e.Seq + 1
				if ok(e.Region) {
					event("alert", e)
					sent++
				}
			}
			if sent > 0 {
				if !flush() {
					return
				}
				sub.Sent.Add(int64(sent))
				if ai, ok := a.state.appliedInfo(evs[len(evs)-1].Version); ok && a.metrics != nil {
					now := time.Now()
					a.metrics.Delivered(now.Sub(ai.at), now.Sub(ai.created), ai.webhook)
				}
			}
			continue
		}
		select {
		case <-r.Context().Done():
			return
		case <-sub.kick:
			event("bye", map[string]string{"reason": "token changed"})
			flush()
			return
		case <-wake:
		case <-sub.dirty: // свіжість даних змінилась (NotifyAll)
			if stale, verified := a.src.Fresh(time.Now()); stale != lastStale {
				lastStale = stale
				event("meta", metaEv{Stale: stale, Verified: jtime{verified}})
				if !flush() {
					return
				}
			}
		case <-ping.C:
			if !a.tokens.Current(tk) || tk.Expired(time.Now()) {
				event("bye", map[string]string{"reason": "token expired or revoked"})
				flush()
				return
			}
			if stale, verified := a.src.Fresh(time.Now()); stale != lastStale {
				lastStale = stale
				event("meta", metaEv{Stale: stale, Verified: jtime{verified}})
			}
			buf.WriteString(": ping\n\n")
			if !flush() {
				return
			}
		}
	}
}

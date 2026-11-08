package main

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Сесії для браузера: сторінка один раз надсилає токен у заголовку (POST /api/v1/session) і
// отримує cookie __Host-ac_session (HttpOnly, Secure, SameSite=Strict). Далі браузер — зокрема
// EventSource, який не вміє заголовків, — працює з cookie, і токен не потрапляє ні в адресу,
// ні в журнали. Сесія діє, доки чинний той самий токен: зміна, rotate чи відкликання токена
// гасять усі його сесії. Обмеження токена (адреси, ліміти, регіони) діють і для сесії.
// Сесії живуть у пам'яті: після перезапуску служби сторінка просто входить знову.

const (
	sessionCookie   = "__Host-ac_session"
	sessionTTL      = 12 * time.Hour
	maxSessionsTok  = 20
	maxSessionsAll  = 20000
	sessionIDBytes  = 32
	sessionIDLength = 43 // base64url без доповнення
)

type session struct {
	tk      *token
	expires time.Time
}

type Sessions struct {
	mu      sync.Mutex
	m       map[string]*session // hash(id) → сесія
	byToken map[string]int
	now     func() time.Time
}

func NewSessions() *Sessions {
	return &Sessions{m: map[string]*session{}, byToken: map[string]int{}, now: time.Now}
}

func (s *Sessions) Create(tk *token) (id string, exp time.Time, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.m) >= maxSessionsAll {
		s.gcLocked()
		if len(s.m) >= maxSessionsAll {
			return "", time.Time{}, false
		}
	}
	if s.byToken[tk.ID] >= maxSessionsTok {
		s.dropOldestLocked(tk.ID)
	}
	var b [sessionIDBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", time.Time{}, false
	}
	id = base64.RawURLEncoding.EncodeToString(b[:])
	exp = s.now().Add(sessionTTL)
	s.m[hashToken(id)] = &session{tk: tk, expires: exp}
	s.byToken[tk.ID]++
	return id, exp, true
}

func (s *Sessions) dropOldestLocked(tokenID string) {
	var oldK string
	var oldT time.Time
	for k, v := range s.m {
		if v.tk.ID == tokenID && (oldK == "" || v.expires.Before(oldT)) {
			oldK, oldT = k, v.expires
		}
	}
	if oldK != "" {
		s.deleteLocked(oldK)
	}
}

func (s *Sessions) deleteLocked(k string) {
	if v := s.m[k]; v != nil {
		delete(s.m, k)
		if s.byToken[v.tk.ID]--; s.byToken[v.tk.ID] <= 0 {
			delete(s.byToken, v.tk.ID)
		}
	}
}

// Get — токен сесії; nil, якщо сесії немає, вона прострочена.
func (s *Sessions) Get(id string) *token {
	if len(id) != sessionIDLength {
		return nil
	}
	k := hashToken(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.m[k]
	if v == nil {
		return nil
	}
	if !s.now().Before(v.expires) {
		s.deleteLocked(k)
		return nil
	}
	return v.tk
}

func (s *Sessions) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleteLocked(hashToken(id))
}

// DropToken — прибрати всі сесії токена (зміна, rotate, відкликання).
func (s *Sessions) DropToken(tokenID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.m {
		if v.tk.ID == tokenID {
			s.deleteLocked(k)
		}
	}
}

func (s *Sessions) gcLocked() {
	now := s.now()
	for k, v := range s.m {
		if !now.Before(v.expires) {
			s.deleteLocked(k)
		}
	}
}

func (s *Sessions) GC() {
	s.mu.Lock()
	s.gcLocked()
	s.mu.Unlock()
}

func (s *Sessions) CountToken(id string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byToken[id]
}

func (s *Sessions) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}

// sameOrigin — для POST/DELETE сесії: якщо браузер надіслав Origin, він має збігатися з Host.
func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true // не браузер або той самий сайт без Origin
	}
	u, err := url.Parse(o)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

// handleSession — POST: увійти токеном із заголовка; DELETE: вийти.
func (a *App) handleSession(w http.ResponseWriter, r *http.Request, ip netip.Addr) {
	if !sameOrigin(r) {
		apiError(w, r, http.StatusForbidden, "cross-origin")
		return
	}
	switch r.Method {
	case http.MethodDelete:
		if c, err := r.Cookie(sessionCookie); err == nil {
			a.sessions.Delete(c.Value)
		}
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, Secure: true,
			HttpOnly: true, SameSite: http.SameSiteStrictMode})
		writeJSON(w, r, 200, struct {
			OK bool `json:"ok"`
		}{true})
	case http.MethodPost:
		raw, viaQuery := rawToken(r)
		if viaQuery {
			raw = "" // увійти можна лише токеном із заголовка
		}
		tk, err := a.tokens.Check(raw, ip, false)
		if err != nil {
			a.reqDenied.Add(1)
			if a.guard.fail(ip, time.Now()) {
				logf("auth: %s blocked for %s after repeated failures", ip, a.guard.banFor)
			}
			apiError(w, r, http.StatusUnauthorized, "unauthorized")
			return
		}
		if ok, retry := tk.bucket.take(time.Now()); !ok {
			retryAfter(w, retry)
			apiError(w, r, http.StatusTooManyRequests, "rate limit")
			return
		}
		id, exp, ok := a.sessions.Create(tk)
		if !ok {
			apiError(w, r, http.StatusServiceUnavailable, "too many sessions")
			return
		}
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: id, Path: "/", Expires: exp,
			MaxAge: int(sessionTTL.Seconds()), Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		writeJSON(w, r, 200, map[string]any{"ok": true, "expires": jtime{exp}})
	default:
		w.Header().Set("Allow", "POST, DELETE")
		apiError(w, r, http.StatusMethodNotAllowed, "method not allowed")
	}
}

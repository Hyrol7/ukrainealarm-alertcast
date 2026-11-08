package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
)

// Керування токенами — лише через локальний Unix-сокет служби (/run/alertcast/admin.sock,
// права 0600). Підключатися можуть тільки root і сама служба (перевіряється SO_PEERCRED).
// У БД пише лише служба, тож зміни діють миттєво, а файли БД не отримують чужого власника.

type adminReq struct {
	Op     string    `json:"op"` // add | list | show | edit | rotate | revoke
	ID     string    `json:"id,omitempty"`
	Spec   TokenSpec `json:"spec"`
	Rotate bool      `json:"rotate,omitempty"`
	Region string    `json:"region,omitempty"` // testregion
	Type   string    `json:"type,omitempty"`
	Level  string    `json:"level,omitempty"`
	PwHash string    `json:"pwHash,omitempty"` // admin-set
	Secret string    `json:"secret,omitempty"`
	Actor  string    `json:"-"` // хто: адреса адміна з панелі; для CLI — порожньо
}

type adminResp struct {
	OK      bool        `json:"ok"`
	Error   string      `json:"error,omitempty"`
	Token   *TokenInfo  `json:"token,omitempty"`
	Secret  string      `json:"secret,omitempty"`
	Tokens  []TokenInfo `json:"tokens,omitempty"`
	Kicked  int         `json:"kicked,omitempty"`
	Message string      `json:"message,omitempty"`
	Test    []TestAlert `json:"test,omitempty"`
}

func listenAdmin(path string) (net.Listener, error) {
	_ = os.Remove(path) // залишок після аварійної зупинки
	old := syscall.Umask(0o177)
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

func peerAllowed(c net.Conn) bool {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return false
	}
	var cred *syscall.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || cerr != nil || cred == nil {
		return false
	}
	return cred.Uid == 0 || int(cred.Uid) == os.Getuid()
}

func (a *App) serveAdmin(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go a.adminConn(c)
	}
}

func (a *App) adminConn(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if !peerAllowed(c) {
		logf("admin: rejected connection from non-root peer")
		return
	}
	var req adminReq
	if err := json.NewDecoder(io.LimitReader(c, 64<<10)).Decode(&req); err != nil {
		json.NewEncoder(c).Encode(adminResp{Error: "bad request"})
		return
	}
	resp := a.admin(req)
	json.NewEncoder(c).Encode(resp)
}

func (a *App) admin(req adminReq) adminResp {
	tree := a.state.Tree()
	fail := func(err error) adminResp { return adminResp{Error: err.Error()} }
	switch req.Op {
	case "list":
		return adminResp{OK: true, Tokens: a.tokens.List()}
	case "show":
		i, ok := a.tokens.Get(req.ID)
		if !ok {
			return fail(fmt.Errorf("токена %s немає", req.ID))
		}
		return adminResp{OK: true, Token: &i}
	case "add":
		i, raw, err := a.tokens.Add(req.Spec, tree, a.cfg.DefaultRPM, a.cfg.DefaultStreams)
		if err != nil {
			return fail(err)
		}
		logf("token %s (%s) created", i.ID, clean(i.Name, 64))
		a.journal.Add("token", req.Actor, "Створено токен «%s» (%s)", i.Name, i.ID)
		return adminResp{OK: true, Token: &i, Secret: raw}
	case "edit", "rotate":
		i, raw, err := a.tokens.Edit(req.ID, req.Spec, tree, req.Op == "rotate")
		if err != nil {
			return fail(err)
		}
		n := a.hub.Kick(req.ID)
		a.sessions.DropToken(req.ID)
		logf("token %s %sed, %d streams closed", i.ID, req.Op, n)
		a.journal.Add("token", req.Actor, map[string]string{"edit": "Змінено токен «%s» (%s)", "rotate": "Новий секрет для «%s» (%s)"}[req.Op], i.Name, i.ID)
		return adminResp{OK: true, Token: &i, Secret: raw, Kicked: n}
	case "test-set":
		if err := a.state.SetTestAlert(req.Region, req.Type, req.Level, time.Now().UTC()); err != nil {
			return fail(err)
		}
		a.hub.Notify(testRoot)
		logf("test region: %s %s → %s", req.Region, strings.ToUpper(orDefault(req.Type, "AIR")), req.Level)
		a.journal.Add("test", req.Actor, "Тестова область: %s %s → %s", req.Region, strings.ToUpper(orDefault(req.Type, "AIR")), req.Level)
		return adminResp{OK: true, Test: a.state.TestAlerts()}
	case "test-clear":
		n := a.state.ClearTest(time.Now(), 0)
		a.hub.Notify(testRoot)
		logf("test region: cleared (%d)", n)
		a.journal.Add("test", req.Actor, "Тестова область: знято всі тривоги (%d)", n)
		return adminResp{OK: true, Test: a.state.TestAlerts()}
	case "admin-status":
		if a.admAuth.Configured() {
			return adminResp{OK: true, Message: "Вхід в адмінку налаштовано (пароль + 2FA). Адреса: " + orNone(a.cfg.AdminListen)}
		}
		return adminResp{OK: true, Message: "Вхід в адмінку ще не налаштовано: sudo alertcast admin setup"}
	case "admin-set":
		if req.Actor != "" { // лише з сокета (root), не з веб-адмінки
			return fail(errors.New("forbidden"))
		}
		if err := a.admAuth.Set(req.PwHash, req.Secret); err != nil {
			return fail(err)
		}
		logf("admin: password and 2FA set, all admin sessions closed")
		a.journal.Add("login", "", "Задано новий пароль і 2FA адміна (усі сесії завершено)")
		return adminResp{OK: true, Message: "Пароль і 2FA збережено. Усі сесії адміна завершено."}
	case "admin-logout":
		n := a.admAuth.LogoutAll()
		a.journal.Add("login", "", "Усі сесії адміна завершено з консолі (%d)", n)
		return adminResp{OK: true, Message: fmt.Sprintf("Завершено сесій: %d", n)}
	case "test-show":
		return adminResp{OK: true, Test: a.state.TestAlerts()}
	case "revoke":
		if err := a.tokens.Revoke(req.ID); err != nil {
			return fail(err)
		}
		n := a.hub.Kick(req.ID)
		a.sessions.DropToken(req.ID)
		logf("token %s revoked, %d streams closed", req.ID, n)
		a.journal.Add("token", req.Actor, "Відкликано токен %s", req.ID)
		return adminResp{OK: true, Kicked: n}
	}
	return fail(fmt.Errorf("невідома операція %q", req.Op))
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// ---------- CLI ----------

func adminCall(sock string, req adminReq) (adminResp, error) {
	c, err := net.DialTimeout("unix", sock, 3*time.Second)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return adminResp{}, errors.New("немає доступу до сокета служби — запустіть через sudo")
		}
		return adminResp{}, fmt.Errorf("служба alertcast не відповідає (%v) — sudo systemctl status alertcast", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return adminResp{}, err
	}
	var resp adminResp
	if err := json.NewDecoder(bufio.NewReader(c)).Decode(&resp); err != nil {
		return adminResp{}, errors.New("служба закрила з'єднання (див. journalctl -u alertcast)")
	}
	if !resp.OK {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}

const tokenUsage = `Керування токенами (потрібен sudo):

  alertcast token add --name "Назва" [параметри]   створити (токен показується один раз)
  alertcast token list                              усі токени й статистика
  alertcast token show ID                           подробиці
  alertcast token edit ID [параметри]               змінити (відкриті потоки токена перепідключаться)
  alertcast token rotate ID                         новий секрет, ті самі налаштування
  alertcast token revoke ID                         відкликати назавжди

Параметри:
  --name "…"            назва (для себе)
  --regions 4,32        дозволені регіони (з усіма вкладеними); "" — усі
  --rpm 60              запитів на хвилину
  --streams 2           одночасних потоків /api/v1/stream (0 — без потоків)
  --expires 2027-06-01  діє до кінця дня; або 90d, 12h; never — безстроково
  --ip 10.77.0.0/24     дозволені адреси/мережі через кому; "" — будь-які
  --allow-query         дозволити токен у адресі (?token=…) — для браузера й простих прошивок
`

var durRe = regexp.MustCompile(`^(\d+)([dhm])$`)

func parseExpires(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	switch s {
	case "", "never", "0":
		return time.Time{}, nil
	}
	if m := durRe.FindStringSubmatch(s); m != nil {
		n, _ := strconv.Atoi(m[1])
		unit := map[string]time.Duration{"d": 24 * time.Hour, "h": time.Hour, "m": time.Minute}[m[2]]
		return now.Add(time.Duration(n) * unit), nil
	}
	if t, err := time.ParseInLocation("2006-01-02", s, time.Local); err == nil {
		return t.AddDate(0, 0, 1).Add(-time.Second), nil // до кінця цього дня (23:59:59)
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("--expires: дата 2027-06-01, тривалість 90d/12h або never")
}

func splitList(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseSpec(fs *flag.FlagSet, args []string) (TokenSpec, []string, error) {
	var sp TokenSpec
	name := fs.String("name", "", "")
	regions := fs.String("regions", "", "")
	rpm := fs.Int("rpm", 0, "")
	streams := fs.Int("streams", 0, "")
	expires := fs.String("expires", "", "")
	ips := fs.String("ip", "", "")
	allowQ := fs.Bool("allow-query", false, "")
	fs.SetOutput(io.Discard)
	// ID може стояти до параметрів: token edit ID --rpm 10
	var pos []string
	for len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		pos, args = append(pos, args[0]), args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return sp, nil, fmt.Errorf("%v\n\n%s", err, tokenUsage)
	}
	pos = append(pos, fs.Args()...)
	var perr error
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "name":
			sp.Name = name
		case "regions":
			v := splitList(*regions)
			sp.Regions = &v
		case "rpm":
			sp.RPM = rpm
		case "streams":
			sp.Streams = streams
		case "expires":
			t, err := parseExpires(*expires, time.Now())
			if err != nil {
				perr = err
			}
			sp.Expires = &t
		case "ip":
			v := splitList(*ips)
			sp.Nets = &v
		case "allow-query":
			sp.AllowQuery = allowQ
		}
	})
	return sp, pos, perr
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Local().Format("2006-01-02 15:04")
}

func orAll(v []string) string {
	if len(v) == 0 {
		return "усі"
	}
	return strings.Join(v, ",")
}

func printToken(i TokenInfo) {
	fmt.Printf("ID:          %s\nНазва:       %s\nСтворено:    %s\nДіє до:      %s\n", i.ID, i.Name, fmtTime(i.Created), fmtTime(i.Expires))
	fmt.Printf("Ліміти:      запитів/хв: %d, потоків: %d\nРегіони:     %s\nАдреси:      %s\n", i.RPM, i.Streams, orAll(i.Regions), orAll(i.Nets))
	fmt.Printf("У адресі:    %v (?token=…)\n", map[bool]string{true: "дозволено", false: "заборонено"}[i.AllowQuery])
	if i.LastSeen.IsZero() {
		fmt.Printf("Активність:  ще не використовувався (відмов: %d)\n", i.Denied)
	} else {
		fmt.Printf("Активність:  запитів %d, відмов %d, востаннє %s з %s\n", i.Requests, i.Denied, fmtTime(i.LastSeen), orDash(i.LastIP))
	}
}

func orDash(s string) string {
	if s == "" || s == "invalid IP" {
		return "—"
	}
	return s
}

func tokenCmd(cfg Config, args []string) int {
	if len(args) == 0 {
		fmt.Print(tokenUsage)
		return 2
	}
	op, rest := args[0], args[1:]
	fs := flag.NewFlagSet("token", flag.ContinueOnError)
	sp, pos, err := parseSpec(fs, rest)
	if err != nil {
		fmt.Fprintln(os.Stderr, "помилка:", err)
		return 2
	}
	req := adminReq{Op: op, Spec: sp}
	needID := map[string]bool{"show": true, "edit": true, "rotate": true, "revoke": true}
	switch {
	case op == "add" || op == "list":
	case needID[op]:
		if len(pos) != 1 {
			fmt.Fprintf(os.Stderr, "помилка: потрібен ID токена: alertcast token %s ID\n", op)
			return 2
		}
		req.ID = pos[0]
	default:
		fmt.Print(tokenUsage)
		return 2
	}
	resp, err := adminCall(cfg.AdminSocket, req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "помилка:", err)
		return 1
	}
	switch op {
	case "list":
		tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tНАЗВА\tДІЄ ДО\tRPM\tПОТОКИ\tРЕГІОНИ\tАДРЕСИ\tЗАПИТІВ\tВІДМОВ\tВОСТАННЄ")
		for _, i := range resp.Tokens {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%s\t%s\t%d\t%d\t%s\n", i.ID, i.Name, fmtTime(i.Expires), i.RPM, i.Streams,
				orAll(i.Regions), orAll(i.Nets), i.Requests, i.Denied, fmtTime(i.LastSeen))
		}
		tw.Flush()
		if len(resp.Tokens) == 0 {
			fmt.Println("(токенів ще немає: sudo alertcast token add --name \"…\")")
		}
	case "revoke":
		fmt.Printf("Токен %s відкликано; закрито потоків: %d\n", req.ID, resp.Kicked)
	default:
		if resp.Token != nil {
			printToken(*resp.Token)
		}
		if resp.Secret != "" {
			fmt.Printf("\nТокен (показується лише зараз, збережіть його):\n\n  %s\n\n", resp.Secret)
		}
		if op == "edit" || op == "rotate" {
			fmt.Printf("Закрито потоків: %d (пристрої перепідключаться)\n", resp.Kicked)
		}
	}
	return 0
}

const testUsage = `Тестова область (потрібен sudo):

  alertcast testregion show                       поточні тестові тривоги
  alertcast testregion set ID РІВЕНЬ [--type T]   РІВЕНЬ: red, yellow, unknown, none (зняти); T: AIR (типово) …
  alertcast testregion clear                      зняти всі

Регіони: 990000 Тестова область
           990100 Тестовий район 1 → 990101, 990102 громади
           990200 Тестовий район 2
Бачать лише токени, яким тестову область дозволено явно (--regions …,990000).
Тривога без змін довше за годину знімається сама.
`

func testRegionCmd(cfg Config, args []string) int {
	if len(args) == 0 {
		fmt.Print(testUsage)
		return 2
	}
	req := adminReq{}
	switch args[0] {
	case "show":
		req.Op = "test-show"
	case "clear":
		req.Op = "test-clear"
	case "set":
		fs := flag.NewFlagSet("testregion", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		typ := fs.String("type", "AIR", "")
		rest := args[1:]
		var pos []string
		for len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			pos, rest = append(pos, rest[0]), rest[1:]
		}
		if err := fs.Parse(rest); err != nil || len(pos)+fs.NArg() != 2 {
			fmt.Print(testUsage)
			return 2
		}
		pos = append(pos, fs.Args()...)
		req = adminReq{Op: "test-set", Region: pos[0], Level: pos[1], Type: *typ}
	default:
		fmt.Print(testUsage)
		return 2
	}
	resp, err := adminCall(cfg.AdminSocket, req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "помилка:", err)
		return 1
	}
	if len(resp.Test) == 0 {
		fmt.Println("Тестових тривог немає.")
		return 0
	}
	for _, t := range resp.Test {
		fmt.Printf("  %s  %-12s %-8s з %s\n", t.Region, t.Type, t.Level, t.Since.Local().Format("15:04:05"))
	}
	return 0
}

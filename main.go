// alertcast — API тривог для пристроїв: бере стан і зміни з alertd, рахує стан регіонів з
// урахуванням ієрархії й віддає їх за токенами з обмеженнями.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

// version задається при збірці: -ldflags "-X main.version=1.0.0"
var version = "dev"

func logf(format string, a ...any) { log.Printf(format, a...) }

func clean(s string, max int) string {
	if len(s) > max {
		s = s[:max] + "…"
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}

type Config struct {
	AlertdURL      string
	PublicListen   string
	PublicIPSource string
	VPNListen      string
	VPNIPSource    string
	VPNAllowQuery  bool
	CFRanges       string
	LocalListen    string
	DBPath         string
	AdminSocket    string
	PublicURL      string
	SiteTitle      string
	StaleAfter     time.Duration
	MaxStreams     int
	MaxStreamsIP   int
	IPRPM          int
	AuthFailLimit  int
	AuthFailWindow time.Duration
	AuthBan        time.Duration
	MaxRegions     int
	DefaultRPM     int
	DefaultStreams int
	AdminListen    string
	AdminIPSource  string
}

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func envDur(k string, def time.Duration) time.Duration {
	v := env(k, "")
	if v == "" {
		return def
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	if n, err := strconv.Atoi(v); err == nil {
		return time.Duration(n) * time.Second
	}
	log.Fatalf("некоректна тривалість %s=%q", k, v)
	return 0
}

func envInt(k string, def int) int {
	v := env(k, "")
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		log.Fatalf("некоректне число %s=%q", k, v)
	}
	return n
}

func loadConfig() Config {
	return Config{
		AlertdURL:      env("ALERTD_URL", "http://127.0.0.1:8788"),
		PublicListen:   env("PUBLIC_LISTEN", "127.0.0.1:8790"),
		PublicIPSource: env("PUBLIC_IP_SOURCE", ipCF),
		VPNListen:      env("VPN_LISTEN", ""),
		VPNIPSource:    env("VPN_IP_SOURCE", ipXFF),
		VPNAllowQuery:  env("VPN_ALLOW_QUERY", "0") == "1",
		CFRanges:       env("CF_RANGES", ""),
		LocalListen:    env("LOCAL_LISTEN", "127.0.0.1:8792"),
		DBPath:         env("DB_PATH", "/var/lib/alertcast/alertcast.db"),
		AdminSocket:    env("ADMIN_SOCKET", "/run/alertcast/admin.sock"),
		PublicURL:      env("PUBLIC_URL", ""),
		SiteTitle:      env("SITE_TITLE", ""),
		StaleAfter:     envDur("STALE_AFTER", 5*time.Minute),
		MaxStreams:     envInt("MAX_STREAMS", 2000),
		MaxStreamsIP:   envInt("MAX_STREAMS_PER_IP", 20),
		IPRPM:          envInt("IP_RPM", 300),
		AuthFailLimit:  envInt("AUTH_FAIL_LIMIT", 10),
		AuthFailWindow: envDur("AUTH_FAIL_WINDOW", 10*time.Minute),
		AuthBan:        envDur("AUTH_BAN", 15*time.Minute),
		MaxRegions:     envInt("MAX_REGIONS", 64),
		DefaultRPM:     envInt("DEFAULT_RPM", 60),
		DefaultStreams: envInt("DEFAULT_STREAMS", 2),
		AdminListen:    env("ADMIN_LISTEN", "127.0.0.1:8793"),
		AdminIPSource:  env("ADMIN_IP_SOURCE", ipXFF),
	}
}

func isLoopback(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateConfig(c Config) error {
	u, err := url.Parse(c.AlertdURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("ALERTD_URL: некоректна адреса %q", c.AlertdURL)
	}
	if u.Scheme == "http" && !isLoopback(u.Host) {
		return errors.New("ALERTD_URL: http дозволено лише для loopback (alertd на цьому ж сервері)")
	}
	if !isLoopback(c.LocalListen) {
		return fmt.Errorf("LOCAL_LISTEN=%s: локальний API — лише loopback", c.LocalListen)
	}
	srcOK := map[string]bool{ipRemote: true, ipCF: true, ipXFF: true}
	if !srcOK[c.PublicIPSource] || !srcOK[c.VPNIPSource] {
		return errors.New("PUBLIC_IP_SOURCE / VPN_IP_SOURCE: remote, cf або xff")
	}
	if c.AdminListen != "" && c.AdminListen != "off" && !isLoopback(c.AdminListen) {
		return fmt.Errorf("ADMIN_LISTEN=%s: адмінка — лише loopback (назовні — через VPN-сайт панелі)", c.AdminListen)
	}
	if !srcOK[c.AdminIPSource] {
		return errors.New("ADMIN_IP_SOURCE: remote, cf або xff")
	}
	if c.PublicListen == "" {
		return errors.New("PUBLIC_LISTEN: потрібна адреса")
	}
	if c.VPNListen != "" && c.VPNListen == c.PublicListen {
		return errors.New("VPN_LISTEN має відрізнятися від PUBLIC_LISTEN")
	}
	if c.CFRanges != "" {
		if _, err := parseRanges(c.CFRanges); err != nil {
			return err
		}
	}
	if c.StaleAfter < 30*time.Second {
		return errors.New("STALE_AFTER ≥ 30s")
	}
	for name, v := range map[string]int{"MAX_STREAMS": c.MaxStreams, "MAX_STREAMS_PER_IP": c.MaxStreamsIP, "IP_RPM": c.IPRPM,
		"AUTH_FAIL_LIMIT": c.AuthFailLimit, "MAX_REGIONS": c.MaxRegions, "DEFAULT_RPM": c.DefaultRPM} {
		if v < 1 {
			return fmt.Errorf("%s ≥ 1", name)
		}
	}
	if c.DefaultRPM > maxRPM || c.DefaultStreams < 0 || c.DefaultStreams > maxStreams || c.MaxRegions > 256 {
		return fmt.Errorf("DEFAULT_RPM ≤ %d, DEFAULT_STREAMS 0–%d, MAX_REGIONS ≤ 256", maxRPM, maxStreams)
	}
	if utf8.RuneCountInString(c.SiteTitle) > 64 || strings.ContainsFunc(c.SiteTitle, unicode.IsControl) {
		return errors.New("SITE_TITLE: до 64 символів, без керівних")
	}
	return nil
}

// loadEnvFile — KEY=VALUE (як EnvironmentFile у systemd); задає лише відсутні змінні.
func loadEnvFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		if !ok || !envKeyRe.MatchString(k) {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		if _, set := os.LookupEnv(k); !set {
			os.Setenv(k, v)
		}
	}
	return nil
}

var envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

const usageText = `alertcast %s — API тривог для пристроїв (у парі з alertd)

  alertcast run              запустити сервіс (так його запускає systemd)
  alertcast token …          керування токенами (alertcast token — довідка)
  alertcast testregion …     тестова область: вигадані тривоги для перевірок
  alertcast admin …          вхід в адмінку: пароль і 2FA (alertcast admin — довідка)
  alertcast check            перевірити службу, зв'язок з alertd і публічну адресу
  alertcast verify           звірити стан з живим ukrainealarm (1 запит до API)
  alertcast version

Налаштування — змінні середовища (/etc/alertcast/alertcast.env).
`

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	cmd := "run"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	if cmd != "run" && cmd != "version" {
		if err := loadEnvFile(env("ENV_FILE", "/etc/alertcast/alertcast.env")); err != nil && !errors.Is(err, fs.ErrNotExist) {
			fmt.Fprintln(os.Stderr, "попередження:", err)
		}
	}
	cfg := loadConfig()
	switch cmd {
	case "run":
		if err := run(cfg); err != nil {
			log.Fatal(err)
		}
	case "token":
		os.Exit(tokenCmd(cfg, os.Args[2:]))
	case "testregion":
		os.Exit(testRegionCmd(cfg, os.Args[2:]))
	case "admin":
		os.Exit(adminCmd(cfg, os.Args[2:], os.Stdin, os.Stdout))
	case "check":
		os.Exit(checkCmd(cfg))
	case "verify":
		os.Exit(verifyCmd(cfg))
	case "version", "-v", "--version":
		fmt.Println(version)
	default:
		fmt.Fprintf(os.Stderr, usageText, version)
		os.Exit(2)
	}
}

func listen(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}
	return ln, nil
}

func publicServer(h http.Handler) *http.Server {
	// WriteTimeout немає: потоки живуть годинами; кожен запис має власний дедлайн (api.go).
	return &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		IdleTimeout: 120 * time.Second, MaxHeaderBytes: 16 << 10}
}

func run(cfg Config) error {
	if err := validateConfig(cfg); err != nil {
		return err
	}
	SetSiteTitle(cfg.SiteTitle)
	if cfg.CFRanges != "" {
		cfRanges = mustRanges(cfg.CFRanges)
	}
	tokens, err := OpenTokens(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("db: %w", err)
	}
	state := NewState()
	hub := NewHub(state.StateOf, cfg.MaxStreams, cfg.MaxStreamsIP)
	src := NewSource(cfg.AlertdURL, state, hub, cfg.StaleAfter)
	app := &App{cfg: cfg, state: state, src: src, tokens: tokens, hub: hub, start: time.Now(), sessions: NewSessions(),
		guard: newIPGuard(cfg.IPRPM, cfg.AuthFailLimit, cfg.AuthFailWindow, cfg.AuthBan)}
	if err := app.attachDB(); err != nil {
		return fmt.Errorf("db: %w", err)
	}

	pubLn, err := listen(cfg.PublicListen)
	if err != nil {
		return err
	}
	var vpnLn net.Listener
	if cfg.VPNListen != "" {
		if vpnLn, err = listen(cfg.VPNListen); err != nil {
			return err
		}
	}
	locLn, err := listen(cfg.LocalListen)
	if err != nil {
		return err
	}
	var webLn net.Listener
	if cfg.AdminListen != "" && cfg.AdminListen != "off" {
		if webLn, err = listen(cfg.AdminListen); err != nil {
			return err
		}
	}
	admLn, err := listenAdmin(cfg.AdminSocket)
	if err != nil {
		return fmt.Errorf("admin socket: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	pub := publicServer(named("public", app.Handler(cfg.PublicIPSource, true)))
	go pub.Serve(pubLn)
	var vpn *http.Server
	if vpnLn != nil {
		vpn = publicServer(named("vpn", app.Handler(cfg.VPNIPSource, cfg.VPNAllowQuery)))
		go vpn.Serve(vpnLn)
	}
	loc := &http.Server{Handler: app.LocalHandler(), ReadHeaderTimeout: 5 * time.Second}
	go loc.Serve(locLn)
	go app.serveAdmin(admLn)
	var web *http.Server
	if webLn != nil {
		web = publicServer(app.AdminHandler())
		go web.Serve(webLn)
	}
	go src.Run(ctx)
	go app.maintenance(ctx)
	app.journal.Add("service", "", "Службу запущено (alertcast %s)", version)
	sdNotify("READY=1")
	go runWatchdog(ctx, watchdogInterval(), app.probe, sdNotify)
	logf("alertcast %s: public %s (ip: %s), vpn %s (ip: %s), admin %s, local %s, alertd %s, %d tokens",
		version, cfg.PublicListen, cfg.PublicIPSource, orNone(cfg.VPNListen), cfg.VPNIPSource, orNone(cfg.AdminListen),
		cfg.LocalListen, cfg.AlertdURL, len(tokens.List()))
	if webLn != nil && !app.admAuth.Configured() {
		logf("admin: login is not configured yet — run: sudo alertcast admin setup")
	}

	<-ctx.Done()
	sdNotify("STOPPING=1")
	logf("shutting down")
	app.journal.Add("service", "", "Службу зупинено")
	admLn.Close()
	hub.Kick("") // потоки завершуються одразу: клієнти перепідключаться до нового процесу
	sctx, c := context.WithTimeout(context.Background(), 5*time.Second)
	defer c()
	pub.Shutdown(sctx)
	if vpn != nil {
		vpn.Shutdown(sctx)
	}
	if web != nil {
		web.Close()
	}
	loc.Close()
	app.metrics.Wait()
	tokens.Close()
	return nil
}

// probe — чи служба справді відповідає: блокування стану, потоків і токенів вільні,
// HTTP-сервер обробляє запити.
func (a *App) probe(ctx context.Context) bool {
	_ = a.state.Version()
	a.hub.Count()
	a.tokens.mu.RLock()
	a.tokens.mu.RUnlock()
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+a.cfg.LocalListen+"/health", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

func orNone(s string) string {
	if s == "" {
		return "off"
	}
	return s
}

// attachDB — метрики й журнал у тій самій БД, що й токени.
func (a *App) attachDB() error {
	m, err := NewMetrics(a.tokens.db)
	if err != nil {
		return err
	}
	j, err := NewJournal(a.tokens.db)
	if err != nil {
		return err
	}
	au, err := NewAdminAuth(a.tokens.db)
	if err != nil {
		return err
	}
	a.metrics, a.journal, a.admAuth = m, j, au
	a.src.metrics, a.src.journal = m, j
	return nil
}

// named — позначити вхід (public | vpn), щоб адмінка бачила, звідки потік.
func named(name string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), listenerKey{}, name)))
	})
}

func (a *App) maintenance(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			a.tokens.FlushStats()
			a.guard.gc(now)
			if n := a.state.ClearTest(now, testTTL); n > 0 {
				a.hub.Notify(testRoot)
				logf("test region: %d alerts cleared after %s without changes", n, testTTL)
			}
			a.sessions.GC()
			a.admAuth.GC()
			total, _ := a.hub.Count()
			a.metrics.Tick(total)
			a.journal.Prune(now)
		}
	}
}

// ---------- check ----------

func checkCmd(cfg Config) int {
	fail := false
	step := func(name string, f func() (string, error)) {
		res, err := f()
		if err != nil {
			fail = true
			fmt.Printf("✗ %-16s %v\n", name, err)
			return
		}
		fmt.Printf("✓ %-16s %s\n", name, res)
	}
	hc := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	getJSON := func(u string, out any) (int, error) {
		resp, err := hc.Get(u)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		return resp.StatusCode, json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
	}
	var st struct {
		Version string `json:"version"`
		Uptime  string `json:"uptime"`
		Source  struct {
			Connected  bool   `json:"connected"`
			Stale      bool   `json:"stale"`
			VerifiedAt string `json:"verifiedAt"`
			LastError  string `json:"lastError"`
		} `json:"source"`
		State struct {
			ActiveAlerts int `json:"activeAlerts"`
			Regions      int `json:"regions"`
		} `json:"state"`
		Tokens  int `json:"tokens"`
		Streams struct {
			Total int `json:"total"`
		} `json:"streams"`
	}
	serviceUp := false
	step("служба", func() (string, error) {
		if _, err := getJSON("http://"+cfg.LocalListen+"/stats", &st); err != nil {
			return "", fmt.Errorf("не відповідає на %s (%v)", cfg.LocalListen, err)
		}
		serviceUp = true
		return fmt.Sprintf("alertcast %s працює %s, токенів %d, потоків %d", st.Version, st.Uptime, st.Tokens, st.Streams.Total), nil
	})
	if serviceUp {
		step("alertd", func() (string, error) {
			switch {
			case !st.Source.Connected:
				return "", fmt.Errorf("немає потоку з alertd (%s): %s", cfg.AlertdURL, orDash(st.Source.LastError))
			case st.Source.Stale:
				return "", fmt.Errorf("дані застаріли: alertd востаннє звіряв стан з API %s", orDash(st.Source.VerifiedAt))
			}
			return fmt.Sprintf("потік відкритий, регіонів %d, активних тривог %d, звірка %s",
				st.State.Regions, st.State.ActiveAlerts, st.Source.VerifiedAt), nil
		})
	} else {
		step("alertd", func() (string, error) {
			var h map[string]any
			if _, err := getJSON(strings.TrimRight(cfg.AlertdURL, "/")+"/health", &h); err != nil {
				return "", fmt.Errorf("недоступний: %v", err)
			}
			return "відповідає", nil
		})
	}
	if serviceUp && cfg.AdminListen != "" && cfg.AdminListen != "off" {
		step("адмінка", func() (string, error) {
			var me struct {
				Configured bool `json:"configured"`
			}
			if _, err := getJSON("http://"+cfg.AdminListen+"/api/me", &me); err != nil {
				return "", fmt.Errorf("не відповідає на %s (%v)", cfg.AdminListen, err)
			}
			if !me.Configured {
				return "", errors.New("вхід не налаштовано: sudo alertcast admin setup")
			}
			return "слухає " + cfg.AdminListen + ", вхід налаштовано (пароль + 2FA)", nil
		})
	}
	if cfg.PublicURL != "" {
		step("публічна адреса", func() (string, error) {
			var body struct {
				OK    bool   `json:"ok"`
				Error string `json:"error"`
			}
			code, err := getJSON(strings.TrimRight(cfg.PublicURL, "/")+"/api/v1/me", &body)
			switch {
			case err != nil && code == 0:
				return "", err
			case code == 401 && body.Error == "unauthorized":
				return "ланцюжок до alertcast працює (запит без токена отримав 401 від alertcast)", nil
			case code == 403:
				return "", errors.New("HTTP 403: блокує CDN або фаєрвол (напр. Cloudflare WAF / Bot Fight Mode)")
			case code == 429:
				return "", errors.New("HTTP 429: ця адреса тимчасово заблокована лімітом alertcast")
			case code == 502 || code == 503 || code == 504:
				return "", fmt.Errorf("HTTP %d: alertcast не запущений або proxy не бачить %s", code, cfg.PublicListen)
			}
			return "", fmt.Errorf("неочікувано: HTTP %d", code)
		})
	}
	if fail {
		return 1
	}
	return 0
}

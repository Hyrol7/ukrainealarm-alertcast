package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

func freePort(t testing.TB) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

type e2e struct {
	t        testing.TB
	env      []string
	pub, vpn string
	loc, adm string
	cmd      *exec.Cmd
	log      *bytes.Buffer
}

func (e *e2e) start() {
	e.t.Helper()
	e.log = &bytes.Buffer{}
	e.cmd = exec.Command(os.Getenv("ALERTCAST_BIN"), "run")
	e.cmd.Env = e.env
	e.cmd.Stdout, e.cmd.Stderr = e.log, e.log
	if err := e.cmd.Start(); err != nil {
		e.t.Fatal(err)
	}
	waitFor(e.t, "alertcast up", func() bool {
		r, err := (&net.Dialer{Timeout: 100 * time.Millisecond}).Dial("tcp", e.loc)
		if err == nil {
			r.Close()
		}
		return err == nil
	})
}

func (e *e2e) stop() {
	e.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error)
	go func() { done <- e.cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			e.t.Fatalf("exit: %v\n%s", err, e.log)
		}
	case <-time.After(8 * time.Second):
		e.cmd.Process.Kill()
		e.t.Fatalf("no graceful stop\n%s", e.log)
	}
}

func (e *e2e) cli(args ...string) (string, error) {
	c := exec.Command(os.Getenv("ALERTCAST_BIN"), args...)
	c.Env = append(e.env, "ENV_FILE=/nonexistent")
	out, err := c.CombinedOutput()
	return string(out), err
}

var tokenRe = regexp.MustCompile(`ac_[A-Za-z0-9_-]{43}`)

func TestBinaryEndToEnd(t *testing.T) {
	if os.Getenv("ALERTCAST_BIN") == "" {
		t.Skip("ALERTCAST_BIN not set")
	}
	fake := newFakeAlertd(t)
	fake.push("10", "AIR", lv("Red", 0))
	dir := t.TempDir()
	e := &e2e{t: t, pub: freePort(t), vpn: freePort(t), loc: freePort(t), adm: freePort(t)}
	e.env = append(os.Environ(),
		"ALERTD_URL="+fake.hs.URL, "PUBLIC_LISTEN="+e.pub, "VPN_LISTEN="+e.vpn, "LOCAL_LISTEN="+e.loc,
		"DB_PATH="+filepath.Join(dir, "ac.db"), "ADMIN_SOCKET="+filepath.Join(dir, "admin.sock"),
		"PUBLIC_URL=http://"+e.pub, "ADMIN_LISTEN="+e.adm)
	// як під systemd: READY=1 після старту і WATCHDOG=1 від живої служби
	nsock := filepath.Join(dir, "notify")
	nl, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: nsock, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer nl.Close()
	e.env = append(e.env, "NOTIFY_SOCKET="+nsock, "WATCHDOG_USEC=600000")
	e.start()
	got := map[string]bool{}
	nl.SetReadDeadline(time.Now().Add(3 * time.Second))
	for buf := make([]byte, 128); !got["READY=1"] || !got["WATCHDOG=1"]; {
		n, err := nl.Read(buf)
		if err != nil {
			t.Fatalf("sd_notify: got %v (%v)", got, err)
		}
		got[string(buf[:n])] = true
	}
	waitFor(t, "fresh", func() bool {
		r := do(t, "http://"+e.loc, "/health", "")
		return r.code == 200
	})
	out, err := e.cli("token", "add", "--name", "e2e лампа", "--regions", "10", "--rpm", "120", "--streams", "1")
	secret := tokenRe.FindString(out)
	if err != nil || secret == "" || !strings.Contains(out, "показується лише зараз") {
		t.Fatalf("token add: %v\n%s", err, out)
	}
	id := regexp.MustCompile(`ID:\s+([0-9a-f]{8})`).FindStringSubmatch(out)[1]
	var r statusResp
	do(t, "http://"+e.pub, "/api/v1/status?regions=101", secret).json(t, &r)
	if r.Regions["101"].State != "active" || r.Regions["101"].Level != "red" {
		t.Fatalf("status via binary: %+v", r)
	}
	if out, err := e.cli("testregion", "set", "990101", "yellow"); err != nil || !strings.Contains(out, "990101") || !strings.Contains(out, "yellow") {
		t.Fatalf("testregion set: %v\n%s", err, out)
	}
	if out, _ := e.cli("testregion", "clear"); !strings.Contains(out, "немає") {
		t.Fatalf("testregion clear: %s", out)
	}
	if out, err := e.cli("admin", "status"); err != nil || !strings.Contains(out, "ще не налаштовано") {
		t.Fatalf("admin status: %v\n%s", err, out)
	}
	if r := do(t, "http://"+e.adm, "/api/me", ""); r.code != 200 || !strings.Contains(r.body, `"configured":false`) {
		t.Fatalf("admin web: %d %s", r.code, r.body)
	}
	if out, _ := e.cli("token", "list"); !strings.Contains(out, id) || !strings.Contains(out, "e2e лампа") {
		t.Fatalf("list:\n%s", out)
	}
	if out, err := e.cli("check"); err == nil || strings.Count(out, "✓") != 3 || !strings.Contains(out, "✗ адмінка") || !strings.Contains(out, "admin setup") {
		t.Fatalf("check (admin not set up yet): %v\n%s", err, out)
	}
	// як після «alertcast admin setup»: той самий запит через сокет
	sec, _ := newTOTPSecret()
	hash, _ := hashPassword("pass-pass-pass")
	if _, err := adminCall(filepath.Join(dir, "admin.sock"), adminReq{Op: "admin-set", PwHash: hash, Secret: sec}); err != nil {
		t.Fatal(err)
	}
	if out, err := e.cli("check"); err != nil || strings.Count(out, "✓") != 4 || !strings.Contains(out, "вхід налаштовано") {
		t.Fatalf("check: %v\n%s", err, out)
	}
	// перезапуск: токен і статистика зберігаються, потоки відновлюються
	e.stop()
	if !strings.Contains(e.log.String(), "shutting down") {
		t.Fatalf("log:\n%s", e.log)
	}
	e.start()
	waitFor(t, "fresh after restart", func() bool { return do(t, "http://"+e.loc, "/health", "").code == 200 })
	if r := do(t, "http://"+e.pub, "/api/v1/me", secret); r.code != 200 || !strings.Contains(r.body, `"requests"`) && r.code != 200 {
		t.Fatalf("token after restart: %d %s", r.code, r.body)
	}
	if out, _ := e.cli("token", "show", id); !regexp.MustCompile(`запитів [1-9]`).MatchString(out) {
		t.Fatalf("stats not persisted:\n%s", out)
	}
	if out, err := e.cli("token", "revoke", id); err != nil || !strings.Contains(out, "відкликано") {
		t.Fatalf("revoke: %v %s", err, out)
	}
	if r := do(t, "http://"+e.pub, "/api/v1/me", secret); r.code != 401 {
		t.Fatalf("revoked: %d", r.code)
	}
	if out, err := e.cli("token", "edit"); err == nil || !strings.Contains(out, "потрібен ID") {
		t.Fatalf("edit without id: %s", out)
	}
	e.stop()
	// alertd недоступний: служба стартує, check показує проблему
	fake.down.Store(true)
	e.start()
	if out, err := e.cli("check"); err == nil || !strings.Contains(out, "✗ alertd") {
		t.Fatalf("check with alertd down:\n%s", out)
	}
	e.stop()
	fmt.Fprint(os.Stderr, "")
}

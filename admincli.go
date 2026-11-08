package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// `alertcast admin …` — вхід в адмінку (потрібен sudo; служба має працювати).

const adminUsage = `Вхід в адмінку (потрібен sudo):
  alertcast admin setup     новий пароль і 2FA (QR для застосунку); усі сесії завершуються
  alertcast admin status    чи налаштовано вхід
  alertcast admin logout    завершити всі сесії адміна
`

func adminCmd(cfg Config, args []string, in io.Reader, out io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(out, adminUsage)
		return 2
	}
	switch args[0] {
	case "status":
		r, err := adminCall(cfg.AdminSocket, adminReq{Op: "admin-status"})
		if err != nil {
			fmt.Fprintln(out, "✗", err)
			return 1
		}
		fmt.Fprintln(out, r.Message)
		return 0
	case "logout":
		r, err := adminCall(cfg.AdminSocket, adminReq{Op: "admin-logout"})
		if err != nil {
			fmt.Fprintln(out, "✗", err)
			return 1
		}
		fmt.Fprintln(out, r.Message)
		return 0
	case "setup":
		return adminSetup(cfg, in, out)
	}
	fmt.Fprint(out, adminUsage)
	return 2
}

func adminSetup(cfg Config, in io.Reader, out io.Writer) int {
	if _, err := adminCall(cfg.AdminSocket, adminReq{Op: "admin-status"}); err != nil {
		fmt.Fprintln(out, "✗", err)
		return 1
	}
	rd := bufio.NewReader(in)
	var pw string
	for {
		p1, err := readSecret(rd, out, "Новий пароль (від 12 символів): ")
		if err != nil {
			return 1
		}
		if len([]rune(p1)) < 12 {
			fmt.Fprintln(out, "Закороткий — потрібно щонайменше 12 символів.")
			continue
		}
		p2, err := readSecret(rd, out, "Ще раз: ")
		if err != nil {
			return 1
		}
		if p1 != p2 {
			fmt.Fprintln(out, "Не збігаються, ще раз.")
			continue
		}
		pw = p1
		break
	}
	secret, err := newTOTPSecret()
	if err != nil {
		fmt.Fprintln(out, "✗", err)
		return 1
	}
	uri := otpauthURI(secret, "admin")
	fmt.Fprintln(out, "\nВідскануйте QR застосунком 2FA (Google Authenticator, Aegis, 1Password…):")
	if q, err := NewQR([]byte(uri)); err == nil {
		fmt.Fprint(out, q.Terminal())
	}
	fmt.Fprintf(out, "Або введіть ключ вручну: %s\n(посилання: %s)\n\n", spaced(secret), uri)
	for tries := 0; ; tries++ {
		fmt.Fprint(out, "Код із застосунку для перевірки: ")
		line, err := rd.ReadString('\n')
		if err != nil && line == "" {
			fmt.Fprintln(out, "\nСкасовано — нічого не змінено.")
			return 1
		}
		if totpMatch(secret, strings.TrimSpace(strings.ReplaceAll(line, " ", "")), time.Now()) >= 0 {
			break
		}
		if tries >= 4 {
			fmt.Fprintln(out, "Код не підходить. Перевірте час на телефоні й сервері. Нічого не змінено.")
			return 1
		}
		fmt.Fprintln(out, "Не підходить, спробуйте наступний код.")
	}
	hash, err := hashPassword(pw)
	if err != nil {
		fmt.Fprintln(out, "✗", err)
		return 1
	}
	r, err := adminCall(cfg.AdminSocket, adminReq{Op: "admin-set", PwHash: hash, Secret: secret})
	if err != nil {
		fmt.Fprintln(out, "✗", err)
		return 1
	}
	fmt.Fprintln(out, "✓", r.Message)
	return 0
}

func spaced(s string) string {
	var b strings.Builder
	for i, c := range s {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// readSecret — рядок без відлуння (якщо ввід — термінал).
func readSecret(rd *bufio.Reader, out io.Writer, prompt string) (string, error) {
	fmt.Fprint(out, prompt)
	fd := os.Stdin.Fd()
	var old syscall.Termios
	isTTY := ioctl(fd, syscall.TCGETS, &old) == nil
	if isTTY {
		t := old
		t.Lflag &^= syscall.ECHO
		ioctl(fd, syscall.TCSETS, &t)
		defer func() { ioctl(fd, syscall.TCSETS, &old); fmt.Fprintln(out) }()
	}
	line, err := rd.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func ioctl(fd uintptr, req uint, t *syscall.Termios) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(req), uintptr(unsafe.Pointer(t))); e != 0 {
		return e
	}
	return nil
}

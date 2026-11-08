package main

import (
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Відомий еталон: "HELLO WORLD"-подібних немає для байтового режиму, тож перевірка —
// розпізнаванням (QR_DIR=… go test -run QR; потім scripts/qrcheck.py) і структурними тестами.
func TestQRStructure(t *testing.T) {
	for _, n := range []int{1, 14, 15, 26, 27, 42, 43, 62, 63, 84, 85, 106, 107, 122, 123, 152, 153, 180, 181, 213} {
		data := []byte(strings.Repeat("x", n))
		q, err := NewQR(data)
		if err != nil {
			t.Fatalf("%d: %v", n, err)
		}
		v := (q.Size - 17) / 4
		if v < 1 || v > 10 {
			t.Fatalf("%d: version %d", n, v)
		}
		// шукачі на місцях, темний модуль
		for _, c := range [][2]int{{0, 0}, {q.Size - 7, 0}, {0, q.Size - 7}} {
			if !q.Dark(c[0], c[1]) || !q.Dark(c[0]+3, c[1]+3) || q.Dark(c[0]+1, c[1]+1) {
				t.Fatalf("%d: finder at %v", n, c)
			}
		}
		if !q.Dark(8, q.Size-8) {
			t.Fatal("dark module")
		}
		if dir := os.Getenv("QR_DIR"); dir != "" {
			writeQRPNG(t, q, filepath.Join(dir, fmt.Sprintf("%03d.png", n)))
			os.WriteFile(filepath.Join(dir, fmt.Sprintf("%03d.txt", n)), data, 0o644)
		}
	}
	if _, err := NewQR(make([]byte, 214)); err == nil {
		t.Fatal("too long accepted")
	}
	if dir := os.Getenv("QR_DIR"); dir != "" {
		for i, s := range []string{"otpauth://totp/alertcast:admin?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=alertcast&algorithm=SHA1&digits=6&period=30",
			"ac_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG", "Тест юнікоду"} {
			q, _ := NewQR([]byte(s))
			writeQRPNG(t, q, filepath.Join(dir, fmt.Sprintf("s%d.png", i)))
			os.WriteFile(filepath.Join(dir, fmt.Sprintf("s%d.txt", i)), []byte(s), 0o644)
		}
	}
	q, _ := NewQR([]byte("x"))
	if svg := q.SVG(); !strings.HasPrefix(svg, "<svg") || !strings.Contains(svg, "M4 4h1v1h-1z") {
		t.Fatalf("svg: %.100s", svg)
	}
	if tm := q.Terminal(); strings.Count(tm, "\n") != (q.Size+4+1)/2 {
		t.Fatalf("terminal lines: %d", strings.Count(tm, "\n"))
	}
}

func writeQRPNG(t testing.TB, q *QR, path string) {
	const s = 8
	n := (q.Size + 8) * s
	img := image.NewGray(image.Rect(0, 0, n, n))
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			mx, my := x/s-4, y/s-4
			c := color.Gray{255}
			if mx >= 0 && my >= 0 && mx < q.Size && my < q.Size && q.Dark(mx, my) {
				c = color.Gray{0}
			}
			img.SetGray(x, y, c)
		}
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	png.Encode(f, img)
}

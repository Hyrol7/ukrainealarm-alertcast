package main

import (
	"errors"
	"fmt"
	"strings"
)

// Мінімальний генератор QR-кодів (ISO/IEC 18004): байтовий режим, рівень корекції M,
// версії 1–10 (до 213 байт). Потрібен для секрету 2FA у терміналі й токена в адмінці —
// без сторонніх залежностей.

type QR struct {
	Size int
	mod  [][]bool // [y][x], true — темний
}

func (q *QR) Dark(x, y int) bool { return q.mod[y][x] }

// рівень M: EC-байтів на блок; блоки групи 1 (кількість, даних), групи 2
var qrM = [11]struct{ ec, b1, d1, b2, d2 int }{
	{}, {10, 1, 16, 0, 0}, {16, 1, 28, 0, 0}, {26, 1, 44, 0, 0}, {18, 2, 32, 0, 0}, {24, 2, 43, 0, 0},
	{16, 4, 27, 0, 0}, {18, 4, 31, 0, 0}, {22, 2, 38, 2, 39}, {22, 3, 36, 2, 37}, {26, 4, 43, 1, 44},
}

var qrAlign = [11][]int{{}, {}, {6, 18}, {6, 22}, {6, 26}, {6, 30}, {6, 34}, {6, 22, 38}, {6, 24, 42}, {6, 26, 46}, {6, 28, 50}}

// ---------- GF(256), поліном 0x11D ----------

var gfExp, gfLog [512]byte

func init() {
	x := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = byte(x)
		gfLog[x] = byte(i)
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11D
		}
	}
	for i := 255; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

// rsEC — n байтів корекції Ріда—Соломона для data.
func rsEC(data []byte, n int) []byte {
	gen := []byte{1} // старший коефіцієнт першим
	for i := 0; i < n; i++ {
		next := make([]byte, len(gen)+1)
		for j, c := range gen {
			next[j] ^= c
			next[j+1] ^= gfMul(c, gfExp[i])
		}
		gen = next
	}
	rem := make([]byte, n)
	for _, d := range data {
		f := d ^ rem[0]
		copy(rem, rem[1:])
		rem[n-1] = 0
		for j := 0; j < n; j++ {
			rem[j] ^= gfMul(gen[j+1], f)
		}
	}
	return rem
}

// ---------- кодування ----------

func NewQR(data []byte) (*QR, error) {
	ver := 0
	for v := 1; v <= 10; v++ {
		t := qrM[v]
		capBits := (t.b1*t.d1 + t.b2*t.d2) * 8
		cnt := 8
		if v >= 10 {
			cnt = 16
		}
		if 4+cnt+len(data)*8 <= capBits {
			ver = v
			break
		}
	}
	if ver == 0 {
		return nil, errors.New("qr: забагато даних")
	}
	t := qrM[ver]
	total := t.b1*t.d1 + t.b2*t.d2

	// бітовий потік: режим 0100, довжина, байти, термінатор, вирівнювання, заповнювачі
	var bits []bool
	put := func(v, n int) {
		for i := n - 1; i >= 0; i-- {
			bits = append(bits, v>>i&1 == 1)
		}
	}
	put(4, 4)
	if ver >= 10 {
		put(len(data), 16)
	} else {
		put(len(data), 8)
	}
	for _, b := range data {
		put(int(b), 8)
	}
	put(0, min(4, total*8-len(bits)))
	for len(bits)%8 != 0 {
		bits = append(bits, false)
	}
	for pad := 0xEC; len(bits) < total*8; pad ^= 0xEC ^ 0x11 {
		put(pad, 8)
	}
	cw := make([]byte, total)
	for i, b := range bits {
		if b {
			cw[i/8] |= 0x80 >> (i % 8)
		}
	}

	// блоки, корекція, перемежування
	var blocks, ecs [][]byte
	off := 0
	for g, n := range []int{t.b1, t.b2} {
		size := t.d1
		if g == 1 {
			size = t.d2
		}
		for i := 0; i < n; i++ {
			b := cw[off : off+size]
			off += size
			blocks = append(blocks, b)
			ecs = append(ecs, rsEC(b, t.ec))
		}
	}
	var out []byte
	for i := 0; i < max(t.d1, t.d2); i++ {
		for _, b := range blocks {
			if i < len(b) {
				out = append(out, b[i])
			}
		}
	}
	for i := 0; i < t.ec; i++ {
		for _, e := range ecs {
			out = append(out, e[i])
		}
	}

	size := ver*4 + 17
	var best *QR
	bestPen := -1
	for mask := 0; mask < 8; mask++ {
		q := qrBuild(ver, size, out, mask)
		if p := q.penalty(); bestPen < 0 || p < bestPen {
			best, bestPen = q, p
		}
	}
	return best, nil
}

func qrBuild(ver, size int, data []byte, mask int) *QR {
	q := &QR{Size: size, mod: make([][]bool, size)}
	fn := make([][]bool, size)
	for i := range q.mod {
		q.mod[i] = make([]bool, size)
		fn[i] = make([]bool, size)
	}
	set := func(x, y int, d bool) { q.mod[y][x], fn[y][x] = d, true }

	for i := 0; i < size; i++ { // лінії синхронізації
		set(6, i, i%2 == 0)
		set(i, 6, i%2 == 0)
	}
	finder := func(cx, cy int) {
		for dy := -4; dy <= 4; dy++ {
			for dx := -4; dx <= 4; dx++ {
				x, y := cx+dx, cy+dy
				if x < 0 || y < 0 || x >= size || y >= size {
					continue
				}
				d := max(abs(dx), abs(dy))
				set(x, y, d != 2 && d != 4)
			}
		}
	}
	finder(3, 3)
	finder(size-4, 3)
	finder(3, size-4)
	al := qrAlign[ver]
	for i, ax := range al {
		for j, ay := range al {
			if (i == 0 && j == 0) || (i == 0 && j == len(al)-1) || (i == len(al)-1 && j == 0) {
				continue
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					set(ax+dx, ay+dy, max(abs(dx), abs(dy)) != 1)
				}
			}
		}
	}
	// формат (рівень M = 00) з BCH(15,5)
	fd := mask
	rem := fd
	for i := 0; i < 10; i++ {
		rem = rem<<1 ^ (rem>>9)*0x537
	}
	fb := (fd<<10 | rem) ^ 0x5412
	bit := func(v, i int) bool { return v>>i&1 == 1 }
	for i := 0; i <= 5; i++ {
		set(8, i, bit(fb, i))
	}
	set(8, 7, bit(fb, 6))
	set(8, 8, bit(fb, 7))
	set(7, 8, bit(fb, 8))
	for i := 9; i < 15; i++ {
		set(14-i, 8, bit(fb, i))
	}
	for i := 0; i < 8; i++ {
		set(size-1-i, 8, bit(fb, i))
	}
	for i := 8; i < 15; i++ {
		set(8, size-15+i, bit(fb, i))
	}
	set(8, size-8, true)
	if ver >= 7 { // версія з BCH(18,6)
		rem := ver
		for i := 0; i < 12; i++ {
			rem = rem<<1 ^ (rem>>11)*0x1F25
		}
		vb := ver<<12 | rem
		for i := 0; i < 18; i++ {
			a, b := size-11+i%3, i/3
			set(a, b, bit(vb, i))
			set(b, a, bit(vb, i))
		}
	}
	// дані зигзагом знизу справа, з маскою
	i := 0
	for right := size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := 0; vert < size; vert++ {
			for j := 0; j < 2; j++ {
				x := right - j
				y := vert
				if (right+1)&2 == 0 {
					y = size - 1 - vert
				}
				if fn[y][x] {
					continue
				}
				d := false
				if i < len(data)*8 {
					d = data[i/8]>>(7-i%8)&1 == 1
					i++
				}
				if qrMask(mask, x, y) {
					d = !d
				}
				q.mod[y][x] = d
			}
		}
	}
	return q
}

func qrMask(m, x, y int) bool {
	switch m {
	case 0:
		return (x+y)%2 == 0
	case 1:
		return y%2 == 0
	case 2:
		return x%3 == 0
	case 3:
		return (x+y)%3 == 0
	case 4:
		return (x/3+y/2)%2 == 0
	case 5:
		return x*y%2+x*y%3 == 0
	case 6:
		return (x*y%2+x*y%3)%2 == 0
	}
	return ((x+y)%2+x*y%3)%2 == 0
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// penalty — оцінка маски (правила стандарту): довгі серії, квадрати 2×2, схожість на
// шукачі, баланс темного.
func (q *QR) penalty() int {
	n, p, dark := q.Size, 0, 0
	at := func(x, y int, col bool) bool {
		if col {
			return q.mod[x][y]
		}
		return q.mod[y][x]
	}
	for _, col := range []bool{false, true} {
		for y := 0; y < n; y++ {
			run := 1
			for x := 1; x <= n; x++ {
				if x < n && at(x, y, col) == at(x-1, y, col) {
					run++
					continue
				}
				if run >= 5 {
					p += run - 2
				}
				run = 1
			}
			for x := 0; x+11 <= n; x++ {
				pat := true
				for k, v := range []bool{true, false, true, true, true, false, true} {
					if at(x+k, y, col) != v {
						pat = false
						break
					}
				}
				if !pat {
					continue
				}
				light := func(a, b int) bool {
					for k := a; k < b; k++ {
						if k >= 0 && k < n && at(k, y, col) {
							return false
						}
					}
					return true
				}
				if light(x-4, x) || light(x+7, x+11) {
					p += 40
				}
			}
		}
	}
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			if q.mod[y][x] {
				dark++
			}
			if x+1 < n && y+1 < n {
				c := q.mod[y][x]
				if q.mod[y][x+1] == c && q.mod[y+1][x] == c && q.mod[y+1][x+1] == c {
					p += 3
				}
			}
		}
	}
	pct := dark * 100 / (n * n)
	return p + abs(pct-50)/5*10
}

// SVG — масштабований малюнок з тихою зоною 4 модулі.
func (q *QR) SVG() string {
	n := q.Size + 8
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges"><rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, n, n, n, n)
	for y := 0; y < q.Size; y++ {
		for x := 0; x < q.Size; x++ {
			if q.mod[y][x] {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", x+4, y+4)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String()
}

// Terminal — для терміналу: два ряди модулів в одному рядку тексту (напівблоки), чорне на
// білому незалежно від теми терміналу.
func (q *QR) Terminal() string {
	const quiet = 2
	n := q.Size
	dark := func(x, y int) bool {
		x, y = x-quiet, y-quiet
		return x >= 0 && y >= 0 && x < n && y < n && q.mod[y][x]
	}
	var b strings.Builder
	for y := 0; y < n+2*quiet; y += 2 {
		b.WriteString("\x1b[30;107m")
		for x := 0; x < n+2*quiet; x++ {
			t, u := dark(x, y), dark(x, y+1)
			switch {
			case t && u:
				b.WriteString("█")
			case t:
				b.WriteString("▀")
			case u:
				b.WriteString("▄")
			default:
				b.WriteString(" ")
			}
		}
		b.WriteString("\x1b[0m\n")
	}
	return b.String()
}

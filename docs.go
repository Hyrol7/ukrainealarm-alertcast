package main

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"net/http"
	"strconv"
)

// Сторінка з описом API (/docs) — статичні файли під жорстким CSP; кнопки «Виконати» шлють
// запити лише на цей же сервер (connect-src 'self'). Токен на сторінці живе лише в пам'яті.

//go:embed www/docs
var docsFiles embed.FS

const docsCSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; " +
	"base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

type staticFile struct {
	body []byte
	ct   string
	etag string
}

var docsStatic = func() map[string]staticFile {
	out := map[string]staticFile{}
	for path, f := range map[string][2]string{
		"/docs":     {"www/docs/index.html", "text/html; charset=utf-8"},
		"/docs.css": {"www/docs/docs.css", "text/css; charset=utf-8"},
		"/docs.js":  {"www/docs/docs.js", "text/javascript; charset=utf-8"},
	} {
		b, err := docsFiles.ReadFile(f[0])
		if err != nil {
			panic(err)
		}
		h := sha256.Sum256(b)
		out[path] = staticFile{b, f[1], `"` + hex.EncodeToString(h[:10]) + `"`}
	}
	return out
}()

func serveDocs(w http.ResponseWriter, r *http.Request) bool {
	f, ok := docsStatic[r.URL.Path]
	if !ok {
		return false
	}
	h := w.Header()
	h.Set("Content-Type", f.ct)
	h.Set("Content-Security-Policy", docsCSP)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-cache")
	h.Set("ETag", f.etag)
	if r.Header.Get("If-None-Match") == f.etag {
		w.WriteHeader(http.StatusNotModified)
		return true
	}
	h.Set("Content-Length", strconv.Itoa(len(f.body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		w.Write(f.body)
	}
	return true
}

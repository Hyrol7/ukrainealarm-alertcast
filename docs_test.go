package main

import (
	"strings"
	"testing"
)

func TestDocsPage(t *testing.T) {
	ta := newTestApp(t)
	r := do(t, ta.pub.URL, "/docs", "")
	if r.code != 200 || !strings.Contains(r.body, "/api/v1/stream") || !strings.Contains(r.hdr.Get("Content-Security-Policy"), "connect-src 'self'") ||
		r.hdr.Get("ETag") == "" {
		t.Fatalf("docs: %d %v", r.code, r.hdr)
	}
	if r2 := do(t, ta.pub.URL, "/docs", "", "If-None-Match", r.hdr.Get("ETag")); r2.code != 304 {
		t.Fatalf("304: %d", r2.code)
	}
	for _, p := range []string{"/docs.js", "/docs.css"} {
		if r := do(t, ta.pub.URL, p, ""); r.code != 200 || r.hdr.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s: %d", p, r.code)
		}
	}
	if r := do(t, ta.vpn.URL, "/docs", ""); r.code != 200 {
		t.Fatalf("docs on vpn: %d", r.code)
	}
	// усі ID операцій зі змісту існують на сторінці
	for _, id := range []string{"op-status", "op-stream", "op-regions", "op-me", "op-session-post", "op-session-delete",
		"op-v3-alerts", "op-v3-alert", "op-v3-status", "op-v3-regions", "schemas", "errors", "test-region", "examples"} {
		if !strings.Contains(r.body, `id="`+id+`"`) || !strings.Contains(r.body, `href="#`+id+`"`) {
			t.Fatalf("toc/anchor %s", id)
		}
	}
}

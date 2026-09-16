package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseVkProxyPath(t *testing.T) {
	host, path, ok := parseVkProxyPath("/v/oauth.vk.com/authorize")
	if !ok || host != "oauth.vk.com" || path != "/authorize" {
		t.Fatalf("got host=%q path=%q ok=%v", host, path, ok)
	}
	host, path, ok = parseVkProxyPath("/v/login.vk.ru/")
	if !ok || host != "login.vk.com" || path != "/" {
		t.Fatalf("ru→com host=%q path=%q ok=%v", host, path, ok)
	}
	if _, _, ok := parseVkProxyPath("/v/evil.com/x"); ok {
		t.Fatal("expected reject")
	}
}

func TestRewriteAbsoluteURLPreservesFragment(t *testing.T) {
	p := &vkOAuthProxy{base: "http://127.0.0.1:9"}
	got := p.rewriteAbsoluteURL("https://oauth.vk.com/blank.html#access_token=tok&expires_in=0")
	if !strings.HasPrefix(got, "http://127.0.0.1:9/v/oauth.vk.com/blank.html#access_token=tok") {
		t.Fatalf("got %q", got)
	}
}

func TestRewriteHTMLRewritesHosts(t *testing.T) {
	p := &vkOAuthProxy{base: "http://127.0.0.1:9"}
	in := `<a href="https://login.vk.com/">x</a><form action="//oauth.vk.ru/authorize">`
	out := p.rewriteHTML(in)
	if !strings.Contains(out, "http://127.0.0.1:9/v/login.vk.com/") {
		t.Fatalf("login rewrite missing: %s", out)
	}
	if !strings.Contains(out, "http://127.0.0.1:9/v/oauth.vk.com/authorize") {
		t.Fatalf("oauth.ru rewrite missing: %s", out)
	}
}

func TestVkOAuthProxyInjectJS(t *testing.T) {
	js := vkOAuthProxyInjectJS("http://127.0.0.1:50999", "http://127.0.0.1:50999/csqtt-vk-oauth-done")
	for _, part := range []string{vkOAuthCallbackPath, vkOAuthProxyPrefix, "access_token=", "127.0.0.1:50999", "toProxy"} {
		if !strings.Contains(js, part) {
			t.Fatalf("inject JS missing %q", part)
		}
	}
}

func TestStartVkOAuthProxyServerLocalOnly(t *testing.T) {
	starts, done, stop, err := startVkOAuthProxyServer()
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if len(starts) < 1 || !strings.Contains(starts[0], "/v/oauth.vk.com/authorize") {
		t.Fatalf("starts=%v", starts)
	}
	if !strings.Contains(done, vkOAuthCallbackPath) {
		t.Fatalf("done=%q", done)
	}
	if !strings.HasPrefix(starts[0], "http://127.0.0.1:") {
		t.Fatalf("start not loopback: %s", starts[0])
	}

	// Callback page must be reachable without upstream.
	res, err := http.Get(done)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || !strings.Contains(string(body), "VK") {
		t.Fatalf("status=%d body=%q", res.StatusCode, body)
	}
}

func TestProxyLocationRewrite(t *testing.T) {
	p := &vkOAuthProxy{base: "http://127.0.0.1:9"}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://oauth.vk.com/blank.html#access_token=abc", http.StatusFound)
	}))
	defer upstream.Close()

	// Direct unit check of rewrite helper (httptest Location often drops fragment).
	loc := p.rewriteLocation("https://oauth.vk.com/blank.html#access_token=abc")
	if !strings.Contains(loc, "/v/oauth.vk.com/blank.html#access_token=abc") {
		t.Fatalf("loc=%q", loc)
	}
}

func TestUnrewriteURL(t *testing.T) {
	p := &vkOAuthProxy{base: "http://127.0.0.1:9"}
	got := p.unrewriteURL("http://127.0.0.1:9/v/login.vk.com/act?x=1")
	if got != "https://login.vk.com/act?x=1" {
		t.Fatalf("got %q", got)
	}
}

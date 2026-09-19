package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseVkProxyPath(t *testing.T) {
	host, path, ok := parseVkProxyPath("/v/oauth.vk.com/authorize")
	if !ok || host != "oauth.vk.com" || path != "/authorize" {
		t.Fatalf("got host=%q path=%q ok=%v", host, path, ok)
	}
	host, path, ok = parseVkProxyPath("/v/login.vk.ru/")
	if !ok || host != "login.vk.ru" || path != "/" {
		t.Fatalf("keep .ru host=%q path=%q ok=%v", host, path, ok)
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
	out := p.rewriteHTML(in, "oauth.vk.com")
	if !strings.Contains(out, "http://127.0.0.1:9/v/login.vk.com/") {
		t.Fatalf("login rewrite missing: %s", out)
	}
	if !strings.Contains(out, "http://127.0.0.1:9/v/oauth.vk.ru/authorize") {
		t.Fatalf("oauth.ru rewrite missing: %s", out)
	}
}

func TestEnsureProxyBase(t *testing.T) {
	p := &vkOAuthProxy{base: "http://127.0.0.1:9"}
	in := `<html><head><base id="base"><title>x</title></head>`
	out := p.ensureProxyBase(in, "m.vk.ru")
	if !strings.Contains(out, `href="/v/m.vk.ru/"`) {
		t.Fatalf("base href missing: %s", out)
	}
	if strings.Count(strings.ToLower(out), "<base") != 1 {
		t.Fatalf("expected single base tag: %s", out)
	}
}

func TestProxyHostFromReferer(t *testing.T) {
	got := proxyHostFromReferer("http://127.0.0.1:9/v/m.vk.ru/login")
	if got != "m.vk.ru" {
		t.Fatalf("got %q", got)
	}
	if proxyHostFromReferer("http://127.0.0.1:9/other") != "" {
		t.Fatal("expected empty")
	}
}

func TestRewriteHTMLRootRelative(t *testing.T) {
	p := &vkOAuthProxy{base: "http://127.0.0.1:9"}
	in := `<link href="/css/a.css"><form action="/act/login"><a href="//login.vk.com/x">x</a>`
	out := p.rewriteHTML(in, "login.vk.com")
	if !strings.Contains(out, `href="/v/login.vk.com/css/a.css"`) {
		t.Fatalf("root css: %s", out)
	}
	if !strings.Contains(out, `action="/v/login.vk.com/act/login"`) {
		t.Fatalf("root action: %s", out)
	}
	if !strings.Contains(out, "http://127.0.0.1:9/v/login.vk.com/x") {
		t.Fatalf("protocol-relative still absolute-rewritten: %s", out)
	}
}

func TestRewriteHTMLSkipsAlreadyProxiedRootRel(t *testing.T) {
	p := &vkOAuthProxy{base: "http://127.0.0.1:9"}
	in := `<a href="/v/oauth.vk.com/authorize">retry</a><link href="/v/oauth.vk.com/css/a.css">`
	out := p.rewriteHTML(in, "oauth.vk.com")
	if strings.Contains(out, "/v/oauth.vk.com/v/oauth.vk.com/") {
		t.Fatalf("nested /v/ rewrite: %s", out)
	}
	if !strings.Contains(out, `href="/v/oauth.vk.com/authorize"`) {
		t.Fatalf("authorize href lost: %s", out)
	}
	if !strings.Contains(out, `href="/v/oauth.vk.com/css/a.css"`) {
		t.Fatalf("css href lost: %s", out)
	}
}

func TestUnwrapVkProxyPath(t *testing.T) {
	host, path, ok := unwrapVkProxyPath("/v/oauth.vk.com/v/oauth.vk.com/v/oauth.vk.com/authorize")
	if !ok || host != "oauth.vk.com" || path != "/authorize" {
		t.Fatalf("got host=%q path=%q ok=%v", host, path, ok)
	}
	got := canonicalVkProxyRequestURI("/v/oauth.vk.com/v/oauth.vk.com/authorize", "x=1")
	if got != "/v/oauth.vk.com/authorize?x=1" {
		t.Fatalf("canonical=%q", got)
	}
}

func TestResolveUpstreamLocationAlreadyProxied(t *testing.T) {
	got := resolveUpstreamLocation("oauth.vk.com", "/v/oauth.vk.com/authorize")
	if got != "https://oauth.vk.com/authorize" {
		t.Fatalf("got %q", got)
	}
}

func TestVkOAuthProxyInjectJSNoSPAHooks(t *testing.T) {
	js := vkOAuthProxyInjectJS("http://127.0.0.1:50999", "http://127.0.0.1:50999/csqtt-vk-oauth-done")
	// Location navigation hooks remount the WebView; host/hostname getters are required
	// so id.vk.ru/auth SPA does not treat document origin as 127.0.0.1 (white screen).
	for _, bad := range []string{"hookLocation", "preferLogin", "hookNavigation", "allowFullNav"} {
		if strings.Contains(js, bad) {
			t.Fatalf("inject must not contain SPA navigation hook %q", bad)
		}
	}
	for _, need := range []string{"toProxy", "hookNet", "rootProxy", "pinBase", "patchLoc", "__csqttLocHost", "Location.prototype"} {
		if !strings.Contains(js, need) {
			t.Fatalf("inject missing net/host proxy hook %q", need)
		}
	}
}

func TestResolveUpstreamLocation(t *testing.T) {
	got := resolveUpstreamLocation("oauth.vk.com", "/blank.html#access_token=abc")
	if got != "https://oauth.vk.com/blank.html#access_token=abc" {
		t.Fatalf("got %q", got)
	}
	got = resolveUpstreamLocation("login.vk.ru", "//m.vk.com/")
	if got != "https://m.vk.com/" {
		t.Fatalf("got %q", got)
	}
}

func TestVkOAuthProxyInjectJS(t *testing.T) {
	js := vkOAuthProxyInjectJS("http://127.0.0.1:50999", "http://127.0.0.1:50999/csqtt-vk-oauth-done")
	for _, part := range []string{vkOAuthCallbackPath, "access_token=", "127.0.0.1:50999", vkOAuthStatusPath, "pollStatus", "hoist"} {
		if !strings.Contains(js, part) {
			t.Fatalf("inject JS missing %q", part)
		}
	}
	if strings.Contains(js, "hookNavigation") || strings.Contains(js, "allowFullNav") || strings.Contains(js, "hookLocation") {
		t.Fatal("inject must not hook Location/Navigation (SPA remount storm)")
	}
	if !strings.Contains(js, "patchLoc") || !strings.Contains(js, "__csqttLocHost") {
		t.Fatal("inject must patch Location.host for id.vk.ru SPA under loopback")
	}
}

func TestRewriteSetCookieForWebView(t *testing.T) {
	in := "remixsid=abc; Domain=.vk.ru; Path=/; HttpOnly; Secure; SameSite=None"
	got := rewriteSetCookieForWebView(in)
	if !strings.Contains(got, "remixsid=abc") {
		t.Fatalf("name lost: %s", got)
	}
	if strings.Contains(strings.ToLower(got), "domain=") {
		t.Fatalf("domain must be dropped: %s", got)
	}
	if strings.Contains(strings.ToLower(got), "secure") {
		t.Fatalf("secure must be dropped: %s", got)
	}
	if !strings.Contains(got, "Path=/") {
		t.Fatalf("path missing: %s", got)
	}
	if !strings.Contains(got, "SameSite=Lax") {
		t.Fatalf("samesite: %s", got)
	}
}

func TestStartVkOAuthProxyServerLocalOnly(t *testing.T) {
	starts, done, stop, err := startVkOAuthProxyServer()
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if len(starts) != 1 || !strings.Contains(starts[0], "/v/oauth.vk.com/authorize") {
		t.Fatalf("starts=%v want …/v/oauth.vk.com/authorize", starts)
	}
	if !strings.Contains(done, vkOAuthCallbackPath) {
		t.Fatalf("done=%q", done)
	}
	if !strings.HasPrefix(starts[0], "http://127.0.0.1:") {
		t.Fatalf("start not loopback: %s", starts[0])
	}

	client := &http.Client{
		Timeout: 3 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			Proxy:             nil,
			DisableKeepAlives: true,
		},
	}
	res, err := client.Get(done)
	if err != nil {
		t.Fatalf("done: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(body), "VK") {
		t.Fatalf("done status=%d body=%q", res.StatusCode, body)
	}

	// Legacy start path redirects into authorize (→ id.vk.ru/auth hop), not feed SPA.
	base := starts[0]
	if i := strings.Index(base, "/v/"); i > 0 {
		base = base[:i]
	}
	res, err = client.Get(base + vkOAuthStartPath)
	if err != nil {
		t.Fatalf("start path: %v", err)
	}
	body, _ = io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("start path want 302, got %d body=%q", res.StatusCode, body)
	}
	if loc := res.Header.Get("Location"); !strings.Contains(loc, "/v/oauth.vk.com/authorize") {
		t.Fatalf("start Location=%q want /v/oauth.vk.com/authorize", loc)
	}

	statusURL := strings.Replace(done, vkOAuthCallbackPath, vkOAuthStatusPath, 1)
	res, err = client.Get(statusURL)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	body, _ = io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(body), `"state":"login"`) {
		t.Fatalf("status want login, got %d %q", res.StatusCode, body)
	}
}

func TestNewVkOAuthHTTPTransportTimeouts(t *testing.T) {
	rt := newVkOAuthHTTPTransport()
	tr, ok := rt.(*http.Transport)
	if !ok || tr == nil {
		t.Fatalf("expected *http.Transport, got %T", rt)
	}
	if tr.ResponseHeaderTimeout < 30*time.Second {
		t.Fatalf("ResponseHeaderTimeout too short: %v", tr.ResponseHeaderTimeout)
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

func TestIsHTMLNavPath(t *testing.T) {
	if !isHTMLNavPath("/login") || !isHTMLNavPath("/") {
		t.Fatal("expected html nav")
	}
	if isHTMLNavPath("/dist/mobile/x.js") || isHTMLNavPath("/css/fonts/a.woff2") {
		t.Fatal("static must not be html nav")
	}
}

func TestClientRequestCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1/", nil)
	if !clientRequestCanceled(r, nil) {
		t.Fatal("expected canceled request context")
	}
	if !clientRequestCanceled(nil, context.Canceled) {
		t.Fatal("expected canceled error")
	}
	if clientRequestCanceled(httptest.NewRequest(http.MethodGet, "http://127.0.0.1/", nil), nil) {
		t.Fatal("live request must not look canceled")
	}
}

func TestIsOAuthTerminalLocation(t *testing.T) {
	if !isOAuthTerminalLocation("https://oauth.vk.com/blank.html#access_token=abc") {
		t.Fatal("blank+token")
	}
	if !isOAuthTerminalLocation("https://oauth.vk.com/blank.html#error=access_denied") {
		t.Fatal("blank+error")
	}
	if isOAuthTerminalLocation("https://oauth.vk.com/authorize?client_id=1") {
		t.Fatal("authorize must not be terminal")
	}
}

func TestUpstreamURLKeyDistinctRuCom(t *testing.T) {
	com := upstreamURLKey("https://oauth.vk.com/authorize?x=1")
	ru := upstreamURLKey("https://oauth.vk.ru/authorize?x=1")
	if com == ru {
		t.Fatalf("com/ru keys must differ: %q", com)
	}
	if upstreamURLKey("https://oauth.vk.com/authorize?x=1#frag") != com {
		t.Fatal("fragment must be ignored")
	}
}

func TestIsHTTPRedirect(t *testing.T) {
	if !isHTTPRedirect(301) || !isHTTPRedirect(302) || !isHTTPRedirect(307) {
		t.Fatal("expected redirect codes")
	}
	if isHTTPRedirect(200) || isHTTPRedirect(404) {
		t.Fatal("non-redirect")
	}
}

func TestParseRetryAfterSec(t *testing.T) {
	h := http.Header{}
	h.Set("Retry-After", "40")
	if got := parseRetryAfterSec(h, 25); got != 40 {
		t.Fatalf("got %d", got)
	}
	h.Set("Retry-After", "3")
	if got := parseRetryAfterSec(h, 25); got != vkOAuth429MinWaitSec {
		t.Fatalf("min clamp got %d", got)
	}
	if got := parseRetryAfterSec(nil, 25); got != 25 {
		t.Fatalf("fallback got %d", got)
	}
}

func TestRateLimitCooldown(t *testing.T) {
	p := &vkOAuthProxy{base: "http://127.0.0.1:9"}
	p.markRateLimited(15)
	wait, ok := p.rateLimitRemaining()
	if !ok || wait < 2 || wait > 16 {
		t.Fatalf("wait=%d ok=%v", wait, ok)
	}
	p.coolUntil = time.Now().Add(-time.Second)
	if _, ok := p.rateLimitRemaining(); ok {
		t.Fatal("expected cooldown expired")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOAuthProxyHopToWebView(t *testing.T) {
	var hits []string
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		hits = append(hits, r.URL.Host+r.URL.Path)
		switch {
		case r.URL.Host == "oauth.vk.com" && r.URL.Path == "/authorize":
			return &http.Response{
				StatusCode: http.StatusFound,
				Header:     http.Header{"Location": []string{"https://id.vk.ru/auth?h=1"}},
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    r,
			}, nil
		case r.URL.Host == "id.vk.ru" && r.URL.Path == "/auth":
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
				Body:       io.NopCloser(strings.NewReader("<html><body>login</body></html>")),
				Request:    r,
			}, nil
		default:
			t.Fatalf("unexpected upstream %s", r.URL.String())
			return nil, nil
		}
	})
	p := &vkOAuthProxy{
		base: "http://127.0.0.1:9",
		client: &http.Client{
			Transport: rt,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9/v/oauth.vk.com/authorize?client_id=1", nil)
	rr := httptest.NewRecorder()
	p.serve(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("code=%d body=%s hits=%v", rr.Code, rr.Body.String(), hits)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "/v/id.vk.ru/auth") || !strings.Contains(loc, "h=1") {
		t.Fatalf("loc=%q hits=%v", loc, hits)
	}
	if len(hits) < 2 {
		t.Fatalf("expected follow, hits=%v", hits)
	}
}

func TestOAuthProxySoftShellLoginServed(t *testing.T) {
	var hits []string
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		hits = append(hits, r.URL.Host+r.URL.Path)
		// Soft-shell document roots bypass to oauth authorize (not m.vk.ru feed SPA).
		if r.URL.Host == "oauth.vk.com" && r.URL.Path == "/authorize" {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
				Body:       io.NopCloser(strings.NewReader("<html><head></head><body>vk-authorize</body></html>")),
				Request:    r,
			}, nil
		}
		t.Fatalf("unexpected upstream %s (soft-shell must bypass to authorize)", r.URL.String())
		return nil, nil
	})
	p := &vkOAuthProxy{
		base: "http://127.0.0.1:9",
		client: &http.Client{
			Transport: rt,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9/v/m.vk.ru/", nil)
	rr := httptest.NewRecorder()
	p.serve(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("soft-shell→authorize want 200, got code=%d loc=%q body=%s hits=%v",
			rr.Code, rr.Header().Get("Location"), rr.Body.String(), hits)
	}
	if !strings.Contains(rr.Body.String(), "vk-authorize") {
		t.Fatalf("body=%q hits=%v", rr.Body.String(), hits)
	}
	if len(hits) != 1 || hits[0] != "oauth.vk.com/authorize" {
		t.Fatalf("hits=%v want oauth.vk.com/authorize", hits)
	}
}

// Soft-shell logos (vk.ru/images/…) must survive WebView cancel via asset coalesce —
// otherwise recover-miss → cancel remounts forever (device logs on 1.2.32).
func TestSoftShellAssetCoalesceSurvivesCancel(t *testing.T) {
	var upstreamHits atomic.Int32
	started := make(chan struct{})
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "vk.ru" || !strings.HasPrefix(r.URL.Path, "/images/") {
			t.Fatalf("unexpected upstream %s", r.URL.String())
			return nil, nil
		}
		upstreamHits.Add(1)
		select {
		case <-started:
		default:
			close(started)
		}
		time.Sleep(80 * time.Millisecond)
		png := []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"image/png"}},
			Body:       io.NopCloser(strings.NewReader(string(png))),
			Request:    r,
		}, nil
	})
	p := &vkOAuthProxy{
		base: "http://127.0.0.1:9",
		client: &http.Client{
			Transport: rt,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	logoURL := "http://127.0.0.1:9/v/vk.ru/images/mobile/icons/vk_logo_color_32_2x.png"

	ctx1, cancel1 := context.WithCancel(context.Background())
	req1 := httptest.NewRequestWithContext(ctx1, http.MethodGet, logoURL, nil)
	rr1 := httptest.NewRecorder()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.serve(rr1, req1)
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream never started")
	}
	cancel1() // WebView abort mid-flight
	wg.Wait()

	req2 := httptest.NewRequest(http.MethodGet, logoURL, nil)
	rr2 := httptest.NewRecorder()
	p.serve(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("coalesce hit want 200, got %d body=%s", rr2.Code, rr2.Body.String())
	}
	if upstreamHits.Load() != 1 {
		t.Fatalf("want single upstream fetch after cancel, hits=%d", upstreamHits.Load())
	}
}

// GET / must soft-serve authorize (bypass feed SPA / bare id.vk.ru/ promo) without a 302.
func TestSoftRootNo302(t *testing.T) {
	var hits []string
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		hits = append(hits, r.URL.Host+r.URL.Path)
		if r.URL.Host == "oauth.vk.com" && r.URL.Path == "/authorize" {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
				Body:       io.NopCloser(strings.NewReader("<html><head></head><body>soft-root-authorize</body></html>")),
				Request:    r,
			}, nil
		}
		t.Fatalf("unexpected upstream %s", r.URL.String())
		return nil, nil
	})
	p := &vkOAuthProxy{
		base: "http://127.0.0.1:9",
		client: &http.Client{
			Transport: rt,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9/", nil)
	req.Header.Set("Referer", "http://127.0.0.1:9/v/m.vk.ru/")
	rr := httptest.NewRecorder()
	p.softServeRoot(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("soft-root want 200 authorize, got code=%d loc=%q body=%s hits=%v",
			rr.Code, rr.Header().Get("Location"), rr.Body.String(), hits)
	}
	if !strings.Contains(rr.Body.String(), "soft-root-authorize") {
		t.Fatalf("body=%q hits=%v", rr.Body.String(), hits)
	}
	if len(hits) != 1 || hits[0] != "oauth.vk.com/authorize" {
		t.Fatalf("hits=%v want oauth.vk.com/authorize", hits)
	}
}

func TestResolveMissHostPreferReferer(t *testing.T) {
	p := &vkOAuthProxy{base: "http://127.0.0.1:9"}
	p.rememberHost("vk.ru")
	host, via := p.resolveMissHost("/images/mobile/icons/vk_logo_color_32_2x.png", "http://127.0.0.1:9/v/m.vk.ru/")
	if host != "m.vk.ru" || via != "referer" {
		t.Fatalf("host=%q via=%q want m.vk.ru/referer", host, via)
	}
}

func TestOAuthProxyHopComToRuAuthorize(t *testing.T) {
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "oauth.vk.com" && r.URL.Path == "/authorize" {
			return &http.Response{
				StatusCode: http.StatusMovedPermanently,
				Header:     http.Header{"Location": []string{"https://oauth.vk.ru/authorize?client_id=1"}},
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    r,
			}, nil
		}
		if r.URL.Host == "oauth.vk.ru" && r.URL.Path == "/authorize" {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
				Body:       io.NopCloser(strings.NewReader("<html><body>ok</body></html>")),
				Request:    r,
			}, nil
		}
		t.Fatalf("unexpected %s", r.URL.String())
		return nil, nil
	})
	p := &vkOAuthProxy{
		base: "http://127.0.0.1:9",
		client: &http.Client{
			Transport: rt,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9/v/oauth.vk.com/authorize?client_id=1", nil)
	rr := httptest.NewRecorder()
	p.serve(rr, req)
	// Bounce WebView onto the final .ru host so Set-Cookie domain matches document URL.
	if rr.Code != http.StatusFound {
		t.Fatalf("code=%d loc=%q body=%s", rr.Code, rr.Header().Get("Location"), rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "/v/oauth.vk.ru/authorize") {
		t.Fatalf("loc=%q", loc)
	}
}

func TestVkOAuthProxyInjectJSMinimal(t *testing.T) {
	js := vkOAuthProxyInjectJS("http://127.0.0.1:9", "http://127.0.0.1:9/csqtt-vk-oauth-done")
	for _, needle := range []string{"pollStatus", "hoist", "pinBase", "MutationObserver", "access_token=", vkOAuthStatusPath, "toProxy", "hookNet", "window.fetch", "XMLHttpRequest.prototype.open", "patchLoc", "__csqttLocHost", "Location.prototype"} {
		if !strings.Contains(js, needle) {
			t.Fatalf("inject missing %q", needle)
		}
	}
	for _, bad := range []string{"hookLocation", "hookNavigation", "allowFullNav"} {
		if strings.Contains(js, bad) {
			t.Fatalf("inject must not contain SPA navigation hook %q", bad)
		}
	}
	if strings.Contains(js, ".replace(/.vk.ru$/i,'.vk.com')") || strings.Contains(js, "replace(/\\.vk\\.ru$/i,'.vk.com')") {
		t.Fatal("inject must not force .vk.ru → .vk.com (breaks id.vk.ru cookies)")
	}
}

func TestBrowserHeaderURLLoopbackOrigin(t *testing.T) {
	p := &vkOAuthProxy{base: "http://127.0.0.1:9"}
	got := p.browserHeaderURL("http://127.0.0.1:9", "id.vk.ru")
	if got != "https://id.vk.ru" {
		t.Fatalf("bare origin: got %q", got)
	}
	got = p.browserHeaderURL("http://127.0.0.1:9/v/id.vk.ru/auth?x=1", "ignored")
	if got != "https://id.vk.ru/auth?x=1" {
		t.Fatalf("proxied referer: got %q", got)
	}
}

func TestInjectProxyScriptIntoHTML(t *testing.T) {
	p := &vkOAuthProxy{base: "http://127.0.0.1:9", doneURL: "http://127.0.0.1:9/csqtt-vk-oauth-done"}
	in := `<!DOCTYPE html><html><head><meta charset="utf-8"></head><body>hi</body></html>`
	out := p.injectProxyScript(in)
	if !strings.Contains(out, "__csqttOauthProxy") || !strings.Contains(out, "pollStatus") {
		t.Fatalf("script not injected: %s", out)
	}
	if i := strings.Index(out, "__csqttOauthProxy"); i < 0 || i > strings.Index(out, "</head>") {
		t.Fatal("inject must land inside <head>")
	}
	out2 := p.injectProxyScript(out)
	if strings.Count(out2, "<script>") != strings.Count(out, "<script>") {
		t.Fatal("double inject")
	}
}

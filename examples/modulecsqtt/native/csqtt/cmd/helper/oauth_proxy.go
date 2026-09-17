package main

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// WebView AntiNet резолвит DNS через VPN приложения (не protect модуля) → ERR_NAME_NOT_RESOLVED
// на oauth.vk.com. Весь OAuth идёт на 127.0.0.1; helper ходит на VK через protect + cookie jar.

const (
	vkOAuthProxyPrefix  = "/v/"
	vkOAuthStartPath    = "/csqtt-vk-oauth-start"
	vkOAuthStatusPath   = "/csqtt-vk-oauth-status"
	vkOAuthProxyMaxBody = 2 << 20
	// Mobile login shell (same family as CSQTT vk.ru → m.vk.ru). Avoid bare vk.ru:
	// hop→WebView bounce vk.ru↔m.vk.ru loops and leaves a white WebView.
	vkOAuthLoginHost = "m.vk.ru"
	vkOAuthLoginPath = "/login"
)

// newVkOAuthHTTPTransport clones protect DialContext from vkHTTP but with long
// ResponseHeaderTimeout — shared vkHTTP uses 8s which breaks oauth.vk.com under load.
func newVkOAuthHTTPTransport() http.RoundTripper {
	var base *http.Transport
	if vkHTTP != nil {
		if t, ok := vkHTTP.Transport.(*http.Transport); ok && t != nil {
			base = t.Clone()
		}
	}
	if base == nil {
		if t, ok := http.DefaultTransport.(*http.Transport); ok && t != nil {
			base = t.Clone()
		} else {
			base = &http.Transport{Proxy: nil, ForceAttemptHTTP2: false}
		}
	}
	base.ResponseHeaderTimeout = 45 * time.Second
	base.TLSHandshakeTimeout = 20 * time.Second
	base.IdleConnTimeout = 90 * time.Second
	base.ExpectContinueTimeout = 5 * time.Second
	base.ForceAttemptHTTP2 = false
	return base
}

var (
	reAbsVKURL = regexp.MustCompile(`(?i)(https?:)?//((?:[a-z0-9-]+\.)*(?:vk\.(?:com|ru)|userapi\.com|vkuseraudio\.net|vk-cdn\.net|vkcc\.net))(/[^"'>\s]*)?`)
	reHostAttr = regexp.MustCompile(`(?i)(https://|http://|//)((?:[a-z0-9-]+\.)*(?:vk\.(?:com|ru)|userapi\.com|vkuseraudio\.net|vk-cdn\.net|vkcc\.net))`)
	// Root-relative "/css/…" on a proxied page would hit 127.0.0.1/css (404). Map to /v/<host>/…
	reRootRelAttr = regexp.MustCompile(`(?i)(\s(?:href|src|action|poster|data|formaction)=)(["'])(/[^"']*)(["'])`)
	reRootRelCSS  = regexp.MustCompile(`(?i)(url\(\s*)(['"]?)(/[^)'"]*)(['"]?\s*\))`)
	// VkTokenScraper-style HTML follow after remixsid login.
	reOAuthJSLocation = regexp.MustCompile(`(?i)location\.href\s*=\s*["']([^"']+)["']`)
	reOAuthGrantLink  = regexp.MustCompile(`(?i)(https://login\.vk\.(?:com|ru)/\?act=grant_access[^"'\s<]+)`)
	// VK ships empty <base id="base">; without href, root-relative /images/… hit 127.0.0.1/images.
	reBaseTag = regexp.MustCompile(`(?i)<base\b[^>]*>`)
)

type vkOAuthProxy struct {
	base    string // http://127.0.0.1:port
	doneURL string // http://127.0.0.1:port/csqtt-vk-oauth-done
	client  *http.Client

	// After VK 429, skip upstream for a while so WebView auto-refresh / dual hops
	// do not burn the rate limit further.
	mu           sync.Mutex
	coolUntil    time.Time
	coolWaitSec  int
	scrapeBusy   bool
	tokenDoneURL string // cached http://127.0.0.1/…/done?access_token=…
	lastHost     string // last successfully proxied VK host (miss recovery)
}

const (
	vkOAuth429DefaultWaitSec = 25
	vkOAuth429MaxWaitSec     = 90
	vkOAuth429MinWaitSec     = 12
	// Follow VK 3xx inside the helper so WebView never sees authorize→authorize
	// self-redirects (common .com↔.ru / cookie hops) which loop forever on loopback.
	vkOAuthMaxUpstreamRedirects = 12
)

func isProxiedVkHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimSuffix(h, ".")
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	switch {
	case h == "vk.com", strings.HasSuffix(h, ".vk.com"):
		return true
	case h == "vk.ru", strings.HasSuffix(h, ".vk.ru"):
		return true
	case h == "userapi.com", strings.HasSuffix(h, ".userapi.com"):
		return true
	case strings.HasSuffix(h, ".vkuseraudio.net"), strings.HasSuffix(h, ".vk-cdn.net"), strings.HasSuffix(h, ".vkcc.net"):
		return true
	default:
		return false
	}
}

// normalizeVkProxyHost lowercases and strips a port. Keep .vk.ru vs .vk.com as-is —
// collapsing TLDs broke VK ID cookies (id.vk.ru Set-Cookie never matched /v/id.vk.com).
func normalizeVkProxyHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	return h
}

func parseVkProxyPath(p string) (host, path string, ok bool) {
	p = strings.TrimPrefix(p, vkOAuthProxyPrefix)
	if p == "" {
		return "", "", false
	}
	i := strings.IndexByte(p, '/')
	if i < 0 {
		if !isProxiedVkHost(p) {
			return "", "", false
		}
		return normalizeVkProxyHost(p), "/", true
	}
	host = p[:i]
	if !isProxiedVkHost(host) {
		return "", "", false
	}
	path = p[i:]
	if path == "" {
		path = "/"
	}
	return normalizeVkProxyHost(host), path, true
}

// unwrapVkProxyPath peels accidental nesting like
// /v/oauth.vk.com/v/oauth.vk.com/authorize → oauth.vk.com + /authorize.
func unwrapVkProxyPath(p string) (host, path string, ok bool) {
	host, path, ok = parseVkProxyPath(p)
	if !ok {
		return "", "", false
	}
	for n := 0; n < 64 && strings.HasPrefix(path, vkOAuthProxyPrefix); n++ {
		h2, p2, ok2 := parseVkProxyPath(path)
		if !ok2 {
			break
		}
		host, path = h2, p2
	}
	return host, path, true
}

// canonicalVkProxyRequestURI rebuilds /v/<host><path>?<query> after unwrapping nests
// so cooldown retry links never deepen /v/oauth.vk.com/v/... chains.
func canonicalVkProxyRequestURI(rawPath, rawQuery string) string {
	host, path, ok := unwrapVkProxyPath(rawPath)
	if !ok {
		if strings.HasPrefix(rawPath, "/") {
			return rawPath
		}
		return vkOAuthStartPath
	}
	out := vkOAuthProxyPrefix + host + path
	if rawQuery != "" {
		out += "?" + rawQuery
	}
	return out
}

func startVkOAuthProxyServer() (startURLs []string, doneURL string, stop func(), err error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", nil, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	doneURL = base + vkOAuthCallbackPath

	jar, err := cookiejar.New(nil)
	if err != nil {
		_ = ln.Close()
		return nil, "", nil, err
	}
	p := &vkOAuthProxy{
		base:    base,
		doneURL: doneURL,
		client: &http.Client{
			Timeout:   90 * time.Second,
			Jar:       jar,
			Transport: newVkOAuthHTTPTransport(),
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc(vkOAuthCallbackPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, `<!DOCTYPE html><html><head><meta charset="utf-8"><title>CSQTT</title></head>`+
			`<body style="font-family:sans-serif;padding:24px;background:#111;color:#eee"><p>Авторизация VK… окно закроется автоматически.</p></body></html>`)
	})
	mux.HandleFunc(vkOAuthStatusPath, p.handleOAuthStatus)
	// Open login HTML directly — intermediate start page stayed on screen when SPA looped.
	loginPath := vkOAuthProxyPrefix + vkOAuthLoginHost + vkOAuthLoginPath
	mux.HandleFunc(vkOAuthStartPath, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, loginPath, http.StatusFound)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/" || path == "" {
			http.Redirect(w, r, loginPath, http.StatusFound)
			return
		}
		if strings.HasPrefix(path, vkOAuthProxyPrefix) {
			p.serve(w, r)
			return
		}
		// Root-relative asset before <base>/rootProxy kicked in — recover host from Referer/lastHost.
		host := proxyHostFromReferer(r.Header.Get("Referer"))
		if host == "" {
			host = p.cachedLastHost()
		}
		if host == "" && (strings.HasPrefix(path, "/images/") || strings.HasPrefix(path, "/css/") || strings.HasPrefix(path, "/js/")) {
			host = vkOAuthLoginHost
		}
		if host != "" {
			r2 := r.Clone(r.Context())
			r2.URL = cloneURLWithPath(r.URL, vkOAuthProxyPrefix+host+path)
			emitLog("CSQTT OAuth proxy: recover miss %s → /v/%s%s", path, host, path)
			p.serve(w, r2)
			return
		}
		emitLog("CSQTT OAuth proxy: miss %s %s (not under /v/)", r.Method, path)
		http.NotFound(w, r)
	})

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 15 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	stop = func() {
		_ = srv.Close()
		_ = ln.Close()
	}

	startURLs = []string{base + loginPath}
	return startURLs, doneURL, stop, nil
}

func mustJSON(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}

func cloneURLWithPath(u *url.URL, path string) *url.URL {
	if u == nil {
		return &url.URL{Path: path}
	}
	out := *u
	out.Path = path
	out.RawPath = ""
	return &out
}

// proxyHostFromReferer recovers /v/<host>/… from a loopback Referer so root-relative
// misses like /images/… can be remapped under the proxy prefix.
func proxyHostFromReferer(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	u, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	host, _, ok := unwrapVkProxyPath(u.Path)
	if !ok {
		return ""
	}
	return host
}

func (p *vkOAuthProxy) authorizeURL(display string) string {
	redirect := url.QueryEscape("https://oauth.vk.ru/blank.html")
	return fmt.Sprintf("%s%soauth.vk.com/authorize?client_id=7793118&scope=1073737727&redirect_uri=%s&display=%s&response_type=token&revoke=1&v=5.199",
		p.base, vkOAuthProxyPrefix, redirect, display)
}

func (p *vkOAuthProxy) handleOAuthStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	p.ingestRequestCookies(r)

	p.mu.Lock()
	if p.tokenDoneURL != "" {
		u := p.tokenDoneURL
		p.mu.Unlock()
		_, _ = fmt.Fprintf(w, `{"state":"ok","url":%s}`, mustJSON(u))
		return
	}
	if p.scrapeBusy {
		p.mu.Unlock()
		_, _ = io.WriteString(w, `{"state":"busy"}`)
		return
	}
	loggedIn := p.jarHasRemixSID()
	if !loggedIn {
		p.mu.Unlock()
		_, _ = io.WriteString(w, `{"state":"login"}`)
		return
	}
	p.scrapeBusy = true
	p.mu.Unlock()

	done, err := p.scrapeAccessToken()
	p.mu.Lock()
	p.scrapeBusy = false
	if err != nil {
		p.mu.Unlock()
		emitLog("CSQTT OAuth scrape: %v", err)
		_, _ = fmt.Fprintf(w, `{"state":"error","detail":%s}`, mustJSON(err.Error()))
		return
	}
	p.tokenDoneURL = done
	p.mu.Unlock()
	emitLog("CSQTT OAuth scrape: access_token ready")
	_, _ = fmt.Fprintf(w, `{"state":"ok","url":%s}`, mustJSON(done))
}

func remixSIDCookieOK(c *http.Cookie) bool {
	if c == nil {
		return false
	}
	switch c.Name {
	case "remixsid", "remixsid_sp", "remixnsid":
	default:
		return false
	}
	v := strings.TrimSpace(c.Value)
	return v != "" && !strings.EqualFold(v, "deleted") && v != "0"
}

func (p *vkOAuthProxy) jarHasRemixSID() bool {
	if p == nil || p.client == nil || p.client.Jar == nil {
		return false
	}
	for _, raw := range []string{
		"https://vk.ru/", "https://vk.com/", "https://m.vk.ru/", "https://m.vk.com/",
		"https://login.vk.ru/", "https://login.vk.com/", "https://id.vk.ru/", "https://id.vk.com/",
	} {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		for _, c := range p.client.Jar.Cookies(u) {
			if remixSIDCookieOK(c) {
				return true
			}
		}
	}
	return false
}

func parseOAuthTokenQuery(loc string) (q string, ok bool) {
	if !strings.Contains(loc, "access_token=") {
		return "", false
	}
	frag := ""
	if i := strings.IndexByte(loc, '#'); i >= 0 {
		frag = loc[i+1:]
	} else if i := strings.IndexByte(loc, '?'); i >= 0 {
		frag = loc[i+1:]
	}
	if !strings.Contains(frag, "access_token=") {
		return "", false
	}
	return frag, true
}

// scrapeAccessToken mirrors CSQTT VkTokenScraper: authorize with jar cookies after remixsid login.
func (p *vkOAuthProxy) scrapeAccessToken() (string, error) {
	endpoint := "https://oauth.vk.com/authorize?client_id=7793118&display=mobile&redirect_uri=https%3A%2F%2Foauth.vk.ru%2Fblank.html&response_type=token&scope=1073737727&v=5.199&revoke=1"
	for hop := 0; hop < vkOAuthMaxUpstreamRedirects; hop++ {
		req, err := http.NewRequest(http.MethodGet, endpoint, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("User-Agent", vkBrowserUA)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		resp, err := p.client.Do(req)
		if err != nil {
			return "", err
		}
		code := resp.StatusCode
		loc := resp.Header.Get("Location")
		body, _ := io.ReadAll(io.LimitReader(resp.Body, vkOAuthProxyMaxBody))
		_ = resp.Body.Close()

		if isHTTPRedirect(code) {
			abs := resolveUpstreamLocation("oauth.vk.com", loc)
			if q, ok := parseOAuthTokenQuery(abs); ok {
				return p.doneURL + "?" + q, nil
			}
			if abs == "" {
				return "", fmt.Errorf("oauth scrape: empty Location")
			}
			endpoint = abs
			continue
		}
		if code != http.StatusOK {
			return "", fmt.Errorf("oauth scrape HTTP %d", code)
		}
		htmlContent := string(body)
		if m := reOAuthJSLocation.FindStringSubmatch(htmlContent); len(m) == 2 {
			target := m[1]
			if q, ok := parseOAuthTokenQuery(target); ok {
				return p.doneURL + "?" + q, nil
			}
			endpoint = target
			continue
		}
		if m := reOAuthGrantLink.FindStringSubmatch(htmlContent); len(m) == 2 {
			endpoint = strings.ReplaceAll(m[1], "&amp;", "&")
			continue
		}
		return "", fmt.Errorf("oauth scrape: no redirect in HTML")
	}
	return "", fmt.Errorf("oauth scrape: too many hops")
}

// rewriteSetCookieForWebView drops Domain/Secure so cookies stick on http://127.0.0.1.
func rewriteSetCookieForWebView(raw string) string {
	parts := strings.Split(raw, ";")
	if len(parts) == 0 {
		return raw
	}
	out := make([]string, 0, len(parts))
	out = append(out, strings.TrimSpace(parts[0]))
	hasPath := false
	for _, part := range parts[1:] {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		low := strings.ToLower(part)
		switch {
		case strings.HasPrefix(low, "domain="):
			continue
		case low == "secure":
			continue
		case strings.HasPrefix(low, "path="):
			out = append(out, "Path=/")
			hasPath = true
		case strings.HasPrefix(low, "samesite="):
			out = append(out, "SameSite=Lax")
		default:
			out = append(out, part)
		}
	}
	if !hasPath {
		out = append(out, "Path=/")
	}
	return strings.Join(out, "; ")
}

func writeProxiedSetCookies(w http.ResponseWriter, h http.Header) {
	if h == nil {
		return
	}
	for _, sc := range h.Values("Set-Cookie") {
		w.Header().Add("Set-Cookie", rewriteSetCookieForWebView(sc))
	}
}

// ingestRequestCookies merges WebView Cookie header into the helper jar so remixsid
// set only in the browser (or after Path=/ rewrite) still feeds VkTokenScraper.
func (p *vkOAuthProxy) ingestRequestCookies(r *http.Request) {
	if p == nil || p.client == nil || p.client.Jar == nil || r == nil {
		return
	}
	cookies := r.Cookies()
	if len(cookies) == 0 {
		return
	}
	for _, raw := range []string{
		"https://vk.ru/", "https://vk.com/", "https://m.vk.ru/", "https://m.vk.com/",
		"https://login.vk.ru/", "https://login.vk.com/", "https://id.vk.ru/", "https://id.vk.com/",
	} {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		p.client.Jar.SetCookies(u, cookies)
	}
}

// Mirror helper jar cookies onto WebView (in-proxy hops never exposed Set-Cookie to the browser).
func (p *vkOAuthProxy) writeJarCookiesToWebView(w http.ResponseWriter) {
	if p == nil || p.client == nil || p.client.Jar == nil {
		return
	}
	seen := map[string]bool{}
	for _, raw := range []string{
		"https://vk.ru/", "https://vk.com/", "https://m.vk.ru/", "https://m.vk.com/",
		"https://login.vk.ru/", "https://login.vk.com/", "https://id.vk.ru/", "https://id.vk.com/",
		"https://oauth.vk.com/", "https://oauth.vk.ru/",
	} {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		for _, c := range p.client.Jar.Cookies(u) {
			key := c.Name + "\x00" + c.Value
			if seen[key] {
				continue
			}
			seen[key] = true
			sc := c.Name + "=" + c.Value + "; Path=/"
			if c.HttpOnly {
				sc += "; HttpOnly"
			}
			w.Header().Add("Set-Cookie", rewriteSetCookieForWebView(sc))
		}
	}
}

func (p *vkOAuthProxy) unrewriteURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	path := u.Path
	if !strings.HasPrefix(path, vkOAuthProxyPrefix) {
		return raw
	}
	host, upPath, ok := parseVkProxyPath(path)
	if !ok {
		return raw
	}
	out := "https://" + host + upPath
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	if u.Fragment != "" {
		out += "#" + u.Fragment
	}
	return out
}

// browserHeaderURL maps WebView Origin/Referer (127.0.0.1 or /v/…) back to a
// real https://<vk-host>… value. Bare loopback Origin has no /v/ path, so
// unrewriteURL alone leaves "http://127.0.0.1:port" and VK APIs reject it.
func (p *vkOAuthProxy) browserHeaderURL(raw, upstreamHost string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}
	if u := p.unrewriteURL(raw); u != raw {
		return u
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return raw
	}
	h := strings.ToLower(u.Hostname())
	if h != "127.0.0.1" && h != "localhost" && h != "::1" {
		return raw
	}
	up := normalizeVkProxyHost(upstreamHost)
	if up == "" {
		return raw
	}
	path := u.EscapedPath()
	if path == "" || path == "/" {
		return "https://" + up
	}
	out := "https://" + up + path
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out
}

// injectProxyScript embeds hoist/fetch hooks into every HTML page the proxy
// serves. AntiNet injectJs may run only on the first navigation; after hop→
// id.vk.ru the SPA otherwise has no rootProxy and APIs die on 127.0.0.1/….
func (p *vkOAuthProxy) injectProxyScript(htmlBody string) string {
	if strings.Contains(htmlBody, "__csqttOauthProxy") {
		return htmlBody
	}
	done := p.doneURL
	if done == "" {
		done = strings.TrimRight(p.base, "/") + vkOAuthCallbackPath
	}
	tag := "<script>" + vkOAuthProxyInjectJS(p.base, done) + "</script>"
	lower := strings.ToLower(htmlBody)
	if i := strings.Index(lower, "<head>"); i >= 0 {
		at := i + len("<head>")
		return htmlBody[:at] + tag + htmlBody[at:]
	}
	if i := strings.Index(lower, "<head "); i >= 0 {
		if j := strings.Index(htmlBody[i:], ">"); j >= 0 {
			at := i + j + 1
			return htmlBody[:at] + tag + htmlBody[at:]
		}
	}
	return tag + htmlBody
}

// ensureProxyBase forces <base href="/v/<host>/"> so root-relative /images/… and
// empty VK <base id="base"> resolve under the proxy prefix instead of 127.0.0.1/.
func (p *vkOAuthProxy) ensureProxyBase(htmlBody, host string) string {
	host = normalizeVkProxyHost(host)
	if host == "" || !isProxiedVkHost(host) {
		return htmlBody
	}
	href := vkOAuthProxyPrefix + host + "/"
	tag := `<base id="base" href="` + href + `">`
	if reBaseTag.MatchString(htmlBody) {
		return reBaseTag.ReplaceAllString(htmlBody, tag)
	}
	lower := strings.ToLower(htmlBody)
	if i := strings.Index(lower, "<head>"); i >= 0 {
		at := i + len("<head>")
		return htmlBody[:at] + tag + htmlBody[at:]
	}
	if i := strings.Index(lower, "<head "); i >= 0 {
		if j := strings.Index(htmlBody[i:], ">"); j >= 0 {
			at := i + j + 1
			return htmlBody[:at] + tag + htmlBody[at:]
		}
	}
	return tag + htmlBody
}

func (p *vkOAuthProxy) rewriteAbsoluteURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}
	frag := ""
	if i := strings.IndexByte(raw, '#'); i >= 0 {
		frag = raw[i:]
		raw = raw[:i]
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw + frag
	}
	if u.Scheme == "" && strings.HasPrefix(raw, "//") {
		u, err = url.Parse("https:" + raw)
		if err != nil {
			return raw + frag
		}
	}
	host := u.Hostname()
	if host == "" || !isProxiedVkHost(host) {
		return raw + frag
	}
	host = normalizeVkProxyHost(host)
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	out := p.base + vkOAuthProxyPrefix + host + path
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	if frag == "" && u.Fragment != "" {
		frag = "#" + u.Fragment
	}
	return out + frag
}

func (p *vkOAuthProxy) rewriteLocation(loc string) string {
	return p.rewriteAbsoluteURL(loc)
}

func (p *vkOAuthProxy) rewriteHTML(body, host string) string {
	body = reAbsVKURL.ReplaceAllStringFunc(body, func(m string) string {
		return p.rewriteAbsoluteURL(m)
	})
	body = reHostAttr.ReplaceAllStringFunc(body, func(m string) string {
		return p.rewriteAbsoluteURL(m)
	})
	host = normalizeVkProxyHost(host)
	if host != "" && isProxiedVkHost(host) {
		prefix := vkOAuthProxyPrefix + host
		body = reRootRelAttr.ReplaceAllStringFunc(body, func(m string) string {
			sub := reRootRelAttr.FindStringSubmatch(m)
			if len(sub) != 5 || strings.HasPrefix(sub[3], "//") {
				return m
			}
			// Already proxied (/v/oauth.vk.com/...) — do not nest.
			if strings.HasPrefix(sub[3], vkOAuthProxyPrefix) {
				return m
			}
			return sub[1] + sub[2] + prefix + sub[3] + sub[4]
		})
		body = reRootRelCSS.ReplaceAllStringFunc(body, func(m string) string {
			sub := reRootRelCSS.FindStringSubmatch(m)
			if len(sub) != 5 || strings.HasPrefix(sub[3], "//") {
				return m
			}
			if strings.HasPrefix(sub[3], vkOAuthProxyPrefix) {
				return m
			}
			return sub[1] + sub[2] + prefix + sub[3] + sub[4]
		})
	}
	return body
}

func resolveUpstreamLocation(host, loc string) string {
	loc = strings.TrimSpace(loc)
	if loc == "" {
		return loc
	}
	if strings.HasPrefix(loc, "//") {
		return "https:" + loc
	}
	if strings.HasPrefix(loc, "/") {
		// Already a proxy path (e.g. /v/oauth.vk.com/authorize) — unwrap instead of nesting.
		if strings.HasPrefix(loc, vkOAuthProxyPrefix) {
			if h, p, ok := unwrapVkProxyPath(loc); ok {
				return "https://" + h + p
			}
		}
		return "https://" + normalizeVkProxyHost(host) + loc
	}
	if strings.Contains(loc, "://") {
		return loc
	}
	return "https://" + normalizeVkProxyHost(host) + "/" + strings.TrimPrefix(loc, "./")
}

func isHTTPRedirect(code int) bool {
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

// OAuth completion (token in fragment) must be exposed to WebView — following
// blank.html upstream would drop the #access_token=… fragment.
func isOAuthTerminalLocation(loc string) bool {
	u, err := url.Parse(strings.TrimSpace(loc))
	if err != nil || u == nil {
		return false
	}
	path := strings.ToLower(u.EscapedPath())
	if strings.HasSuffix(path, "/blank.html") || path == "/blank.html" {
		return true
	}
	if strings.Contains(u.Fragment, "access_token=") || strings.Contains(u.Fragment, "error=") {
		return true
	}
	if strings.Contains(u.RawQuery, "access_token=") || strings.Contains(u.RawQuery, "error=") {
		return true
	}
	return false
}

// upstreamURLKey ignores fragments for redirect-loop detection. Keep .vk.ru vs
// .vk.com distinct so the first com→ru hop is followed (normalizing would false-positive).
func upstreamURLKey(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil {
		return strings.ToLower(strings.TrimSpace(raw))
	}
	host := strings.ToLower(u.Hostname())
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return host + path + "?" + u.RawQuery
}

func shouldDropProxiedHeader(name string) bool {
	switch strings.ToLower(name) {
	case "content-length", "content-encoding", "transfer-encoding", "set-cookie", "location":
		return true
	case "content-security-policy", "content-security-policy-report-only",
		"x-frame-options", "cross-origin-opener-policy", "cross-origin-embedder-policy",
		"cross-origin-resource-policy", "report-to", "nel", "clear-site-data",
		"permissions-policy", "document-policy", "strict-transport-security":
		return true
	default:
		return false
	}
}

func parseRetryAfterSec(h http.Header, fallback int) int {
	wait := fallback
	if wait < vkOAuth429MinWaitSec {
		wait = vkOAuth429MinWaitSec
	}
	if wait > vkOAuth429MaxWaitSec {
		wait = vkOAuth429MaxWaitSec
	}
	if h == nil {
		return wait
	}
	ra := strings.TrimSpace(h.Get("Retry-After"))
	if ra == "" {
		return wait
	}
	if sec, err := strconv.Atoi(ra); err == nil && sec > 0 {
		if sec < vkOAuth429MinWaitSec {
			sec = vkOAuth429MinWaitSec
		}
		if sec > vkOAuth429MaxWaitSec {
			sec = vkOAuth429MaxWaitSec
		}
		return sec
	}
	if t, err := http.ParseTime(ra); err == nil {
		sec := int(time.Until(t).Seconds())
		if sec < vkOAuth429MinWaitSec {
			sec = vkOAuth429MinWaitSec
		}
		if sec > vkOAuth429MaxWaitSec {
			sec = vkOAuth429MaxWaitSec
		}
		return sec
	}
	return wait
}

func (p *vkOAuthProxy) markRateLimited(waitSec int) {
	if waitSec < vkOAuth429MinWaitSec {
		waitSec = vkOAuth429MinWaitSec
	}
	if waitSec > vkOAuth429MaxWaitSec {
		waitSec = vkOAuth429MaxWaitSec
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	until := time.Now().Add(time.Duration(waitSec) * time.Second)
	if until.After(p.coolUntil) {
		p.coolUntil = until
		p.coolWaitSec = waitSec
	}
}

func (p *vkOAuthProxy) rateLimitRemaining() (waitSec int, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	left := time.Until(p.coolUntil)
	if left <= 0 {
		return 0, false
	}
	sec := int(left.Seconds()) + 1
	if sec < 2 {
		sec = 2
	}
	return sec, true
}

func (p *vkOAuthProxy) writeRateLimitPage(w http.ResponseWriter, retryURL string, waitSec int) {
	detail := fmt.Sprintf(
		"VK вернул 429 (слишком много запросов к oauth). Подождите ~%d с — окно само повторит. Не закрывайте до входа. Если часто срывается: в настройках CSQTT поставьте «Режим хешей → Ручной» и «Режим кредов → Авто» — вход в VK не нужен.",
		waitSec)
	p.writeRetryPage(w, "Слишком много запросов к VK", detail, retryURL, waitSec)
}

func (p *vkOAuthProxy) writeRetryPage(w http.ResponseWriter, title, detail, retryURL string, waitSec int) {
	if waitSec < 2 {
		waitSec = 4
	}
	if retryURL == "" {
		retryURL = vkOAuthStartPath
	}
	escTitle := html.EscapeString(title)
	escDetail := html.EscapeString(detail)
	escRetry := html.EscapeString(retryURL)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="utf-8">`+
		`<meta http-equiv="refresh" content="%d;url=%s">`+
		`<title>%s</title></head>`+
		`<body style="font-family:sans-serif;padding:24px;background:#111;color:#eee;line-height:1.45">`+
		`<h2 style="margin:0 0 12px">%s</h2>`+
		`<p style="opacity:.85;max-width:36em">%s</p>`+
		`<p>Повтор через %d с…</p>`+
		`<p><a style="color:#8cf" href="%s">Повторить сейчас</a></p>`+
		`<script>setTimeout(function(){location.replace(%s);},%d);</script>`+
		`</body></html>`,
		waitSec, escRetry, escTitle, escTitle, escDetail, waitSec, escRetry, mustJSON(retryURL), waitSec*1000)
}

func (p *vkOAuthProxy) cachedLastHost() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastHost
}

func (p *vkOAuthProxy) rememberHost(host string) {
	host = normalizeVkProxyHost(host)
	if host == "" || !isProxiedVkHost(host) {
		return
	}
	p.mu.Lock()
	p.lastHost = host
	p.mu.Unlock()
}

func (p *vkOAuthProxy) serve(w http.ResponseWriter, r *http.Request) {
	p.ingestRequestCookies(r)
	host, path, ok := unwrapVkProxyPath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	p.rememberHost(host)
	rawQuery := r.URL.RawQuery
	up := &url.URL{
		Scheme:   "https",
		Host:     host,
		Path:     path,
		RawQuery: rawQuery,
	}
	retrySelf := canonicalVkProxyRequestURI(r.URL.Path, rawQuery)
	if !strings.HasPrefix(retrySelf, "/") {
		retrySelf = vkOAuthStartPath
	}

	// Local cooldown after 429: do not hit VK again while WebView refreshes.
	if wait, cooling := p.rateLimitRemaining(); cooling {
		emitLog("CSQTT OAuth proxy: cooldown %ds — skip upstream %s %s", wait, r.Method, up.Host+up.Path)
		p.writeRateLimitPage(w, retrySelf, wait)
		return
	}

	var bodyBytes []byte
	if r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
		bodyBytes, _ = io.ReadAll(io.LimitReader(r.Body, vkOAuthProxyMaxBody))
		_ = r.Body.Close()
	}

	started := time.Now()
	var resp *http.Response
	var lastErr error
	// Transport errors only — never re-hammer authorize after 429 (makes limit worse).
	const maxTransportAttempts = 3
	for attempt := 1; attempt <= maxTransportAttempts; attempt++ {
		var body io.Reader
		if len(bodyBytes) > 0 {
			body = strings.NewReader(string(bodyBytes))
		}
		req, err := http.NewRequestWithContext(r.Context(), r.Method, up.String(), body)
		if err != nil {
			emitLog("CSQTT OAuth proxy: build %s %s: %v", r.Method, up.Host+up.Path, err)
			p.writeRetryPage(w, "Ошибка запроса VK", err.Error(), vkOAuthStartPath, 3)
			return
		}
		copyHopHeaders(r.Header, req.Header)
		req.Header.Del("Accept-Encoding")
		req.Header.Set("Accept-Encoding", "identity")
		if req.Header.Get("User-Agent") == "" {
			req.Header.Set("User-Agent", vkBrowserUA)
		}
		if ref := r.Header.Get("Referer"); ref != "" {
			req.Header.Set("Referer", p.browserHeaderURL(ref, host))
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			req.Header.Set("Origin", p.browserHeaderURL(origin, host))
		}
		req.Host = host
		if len(bodyBytes) > 0 {
			req.ContentLength = int64(len(bodyBytes))
		}

		resp, lastErr = p.client.Do(req)
		if lastErr == nil && resp != nil && resp.StatusCode == http.StatusTooManyRequests {
			waitSec := parseRetryAfterSec(resp.Header, vkOAuth429DefaultWaitSec)
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			_ = resp.Body.Close()
			resp = nil
			p.markRateLimited(waitSec)
			emitLog("CSQTT OAuth proxy: 429 %s %s wait=%ds after %s",
				r.Method, up.Host+up.Path, waitSec, time.Since(started).Round(time.Millisecond))
			p.writeRateLimitPage(w, retrySelf, waitSec)
			return
		}
		if lastErr == nil && resp != nil {
			break
		}
		status := 0
		if resp != nil {
			status = resp.StatusCode
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			_ = resp.Body.Close()
			resp = nil
		}
		emitLog("CSQTT OAuth proxy: attempt %d/%d %s %s status=%d err=%v (%s)",
			attempt, maxTransportAttempts, r.Method, up.Host+up.Path, status, lastErr, time.Since(started).Round(time.Millisecond))
		if attempt < maxTransportAttempts {
			time.Sleep(time.Duration(attempt) * 1600 * time.Millisecond)
		}
	}
	if lastErr != nil {
		detail := lastErr.Error()
		title := "VK не ответил вовремя"
		if strings.Contains(detail, "timeout") || strings.Contains(detail, "Timeout") {
			title = "Таймаут ответа VK"
			detail = "Сервер oauth.vk.com долго не отдаёт заголовки. Обычно помогает повтор через несколько секунд (роуминг/нагрузка)."
		}
		emitLog("CSQTT OAuth proxy: FAIL %s %s after %s: %v", r.Method, up.Host+up.Path, time.Since(started).Round(time.Millisecond), lastErr)
		p.writeRetryPage(w, title, detail, retrySelf, 5)
		return
	}
	if resp == nil {
		p.writeRetryPage(w, "Пустой ответ VK", "Нет HTTP-ответа от oauth.", retrySelf, 5)
		return
	}

	// Follow non-terminal redirects in-proxy (cookie jar). Passing authorize→301→authorize
	// back to WebView caused infinite loops on Android (v1.2.19 log).
	seen := map[string]bool{}
	method := r.Method
	for hop := 0; hop < vkOAuthMaxUpstreamRedirects && resp != nil && isHTTPRedirect(resp.StatusCode); hop++ {
		redirStatus := resp.StatusCode
		rawLoc := resp.Header.Get("Location")
		if rawLoc == "" {
			break
		}
		absLoc := resolveUpstreamLocation(host, rawLoc)
		shortLoc := absLoc
		if len(shortLoc) > 120 {
			shortLoc = shortLoc[:117] + "..."
		}
		emitLog("CSQTT OAuth proxy: OK %s %s → %d Location=%s (%s)",
			method, host+path, redirStatus, shortLoc, time.Since(started).Round(time.Millisecond))

		if isOAuthTerminalLocation(absLoc) {
			for k, vv := range resp.Header {
				if shouldDropProxiedHeader(k) {
					continue
				}
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			writeProxiedSetCookies(w, resp.Header)
			p.writeJarCookiesToWebView(w)
			w.Header().Set("Location", p.rewriteLocation(absLoc))
			w.Header().Set("Cache-Control", "no-store")
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			_ = resp.Body.Close()
			w.WriteHeader(redirStatus)
			return
		}

		key := upstreamURLKey(absLoc)
		if seen[key] {
			emitLog("CSQTT OAuth proxy: redirect loop at %s — stop follow", key)
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			_ = resp.Body.Close()
			p.writeRetryPage(w, "Цикл редиректа VK",
				"oauth.vk.com отвечает 301 на тот же authorize. Подождите и повторите, либо «Режим хешей → Ручной» + «Креды → Авто».",
				vkOAuthStartPath, 6)
			return
		}
		seen[key] = true

		nextURL, err := url.Parse(absLoc)
		if err != nil || nextURL.Host == "" {
			break
		}
		if !isProxiedVkHost(nextURL.Hostname()) {
			break
		}

		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		resp = nil

		nextMethod := method
		switch redirStatus {
		case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther:
			nextMethod = http.MethodGet
			bodyBytes = nil
		}

		// Follow Location host as-is (.vk.ru stays .vk.ru) — do not force .com.
		nextHost := strings.ToLower(nextURL.Hostname())
		followURL := &url.URL{
			Scheme:   "https",
			Host:     nextHost,
			Path:     nextURL.Path,
			RawQuery: nextURL.RawQuery,
		}
		if followURL.Path == "" {
			followURL.Path = "/"
		}

		var body io.Reader
		if len(bodyBytes) > 0 && nextMethod != http.MethodGet && nextMethod != http.MethodHead {
			body = strings.NewReader(string(bodyBytes))
		}
		req, err := http.NewRequestWithContext(r.Context(), nextMethod, followURL.String(), body)
		if err != nil {
			p.writeRetryPage(w, "Ошибка редиректа VK", err.Error(), vkOAuthStartPath, 3)
			return
		}
		copyHopHeaders(r.Header, req.Header)
		req.Header.Del("Accept-Encoding")
		req.Header.Set("Accept-Encoding", "identity")
		if req.Header.Get("User-Agent") == "" {
			req.Header.Set("User-Agent", vkBrowserUA)
		}
		req.Header.Set("Referer", "https://"+host+path)
		req.Header.Set("Origin", "https://"+nextHost)
		req.Host = nextHost
		if body != nil {
			req.ContentLength = int64(len(bodyBytes))
		}

		resp, lastErr = p.client.Do(req)
		if lastErr != nil {
			emitLog("CSQTT OAuth proxy: follow FAIL %s %s: %v", nextMethod, nextHost+followURL.Path, lastErr)
			p.writeRetryPage(w, "VK не ответил вовремя", lastErr.Error(), retrySelf, 5)
			return
		}
		if resp != nil && resp.StatusCode == http.StatusTooManyRequests {
			waitSec := parseRetryAfterSec(resp.Header, vkOAuth429DefaultWaitSec)
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			_ = resp.Body.Close()
			p.markRateLimited(waitSec)
			emitLog("CSQTT OAuth proxy: 429 on follow %s %s wait=%ds", nextMethod, nextHost+followURL.Path, waitSec)
			p.writeRateLimitPage(w, retrySelf, waitSec)
			return
		}
		host = nextHost
		path = followURL.Path
		rawQuery = followURL.RawQuery
		method = nextMethod
	}

	if resp == nil {
		p.writeRetryPage(w, "Пустой ответ VK", "Нет HTTP-ответа после редиректов.", retrySelf, 5)
		return
	}
	if isHTTPRedirect(resp.StatusCode) {
		rawLoc := resp.Header.Get("Location")
		absLoc := resolveUpstreamLocation(host, rawLoc)
		if isOAuthTerminalLocation(absLoc) {
			for k, vv := range resp.Header {
				if shouldDropProxiedHeader(k) {
					continue
				}
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			writeProxiedSetCookies(w, resp.Header)
			p.writeJarCookiesToWebView(w)
			w.Header().Set("Location", p.rewriteLocation(absLoc))
			w.Header().Set("Cache-Control", "no-store")
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			_ = resp.Body.Close()
			w.WriteHeader(resp.StatusCode)
			return
		}
		// Still a redirect after follow budget / non-VK break: do not bounce WebView.
		emitLog("CSQTT OAuth proxy: stop exposing redirect %d %s → %s", resp.StatusCode, host+path, absLoc)
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		p.writeRetryPage(w, "Слишком много редиректов VK",
			"OAuth-прокси остановил цепочку 3xx, чтобы WebView не зациклился. Повторите вход или «Хеши → Ручной» + «Креды → Авто».",
			vkOAuthStartPath, 5)
		return
	}

	// After in-proxy follow, WebView URL still shows the first hop (e.g. /v/oauth…/authorize)
	// while the body is id.vk.ru. Relative + XHR/fetch then miss the proxy. Bounce once
	// to the final host as-is (.ru stays .ru) so cookies match the document origin.
	reqKey := upstreamURLKey((&url.URL{Scheme: "https", Host: normalizeVkProxyHost(up.Host), Path: up.Path, RawQuery: up.RawQuery}).String())
	finalKey := upstreamURLKey((&url.URL{Scheme: "https", Host: normalizeVkProxyHost(host), Path: path, RawQuery: rawQuery}).String())
	if reqKey != finalKey {
		writeProxiedSetCookies(w, resp.Header)
		p.writeJarCookiesToWebView(w)
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		bounce := (&url.URL{Scheme: "https", Host: normalizeVkProxyHost(host), Path: path, RawQuery: rawQuery}).String()
		loc := p.rewriteLocation(bounce)
		baseTrim := strings.TrimRight(p.base, "/")
		if strings.HasPrefix(loc, baseTrim) {
			loc = strings.TrimPrefix(loc, baseTrim)
			if loc == "" || loc[0] != '/' {
				loc = "/" + loc
			}
		}
		emitLog("CSQTT OAuth proxy: hop→WebView 302 %s → %s", up.Host+up.Path, loc)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Location", loc)
		w.WriteHeader(http.StatusFound)
		return
	}

	defer resp.Body.Close()
	emitLog("CSQTT OAuth proxy: OK %s %s → %d (%s)", method, host+path, resp.StatusCode, time.Since(started).Round(time.Millisecond))

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	rewriteBody := strings.Contains(ct, "text/html") || strings.Contains(ct, "javascript") || strings.Contains(ct, "json") || strings.Contains(ct, "text/css")

	for k, vv := range resp.Header {
		if shouldDropProxiedHeader(k) {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	writeProxiedSetCookies(w, resp.Header)
	if strings.Contains(ct, "text/html") {
		p.writeJarCookiesToWebView(w)
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		w.Header().Set("Location", p.rewriteLocation(resolveUpstreamLocation(host, loc)))
	}
	w.Header().Set("Cache-Control", "no-store")

	if !rewriteBody {
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, io.LimitReader(resp.Body, vkOAuthProxyMaxBody*4))
		return
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, vkOAuthProxyMaxBody))
	if err != nil {
		p.writeRetryPage(w, "Обрыв ответа VK", err.Error(), retrySelf, 4)
		return
	}
	bodyStr := string(raw)
	if resp.StatusCode == http.StatusOK && (strings.Contains(bodyStr, "429 Too Many Requests") || strings.Contains(strings.ToLower(bodyStr), "kittenx")) {
		waitSec := parseRetryAfterSec(resp.Header, vkOAuth429DefaultWaitSec)
		p.markRateLimited(waitSec)
		p.writeRateLimitPage(w, retrySelf, waitSec)
		return
	}
	out := p.rewriteHTML(bodyStr, host)
	if strings.Contains(ct, "text/html") {
		out = p.ensureProxyBase(out, host)
		before := len(out)
		out = p.injectProxyScript(out)
		if len(out) != before {
			emitLog("CSQTT OAuth proxy: inject HTML %s (%d→%d B)", host+path, before, len(out))
		}
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(out)))
	w.WriteHeader(resp.StatusCode)
	_, _ = io.WriteString(w, out)
}

func copyHopHeaders(src, dst http.Header) {
	for k, vv := range src {
		lk := strings.ToLower(k)
		switch lk {
		case "host", "content-length", "connection", "transfer-encoding", "accept-encoding", "cookie":
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func vkOAuthProxyInjectJS(base, doneURL string) string {
	b, _ := json.Marshal(strings.TrimRight(base, "/"))
	d, _ := json.Marshal(strings.TrimSpace(doneURL))
	prefix, _ := json.Marshal(vkOAuthProxyPrefix)
	marker, _ := json.Marshal(vkOAuthCallbackPath)
	status, _ := json.Marshal(strings.TrimRight(base, "/") + vkOAuthStatusPath)
	// Injected first in <head>. Must install Location hooks before VK SPA runs:
	// rewriteAbsoluteURL turns canonical https://m.vk.ru/login into the loopback
	// proxy URL; assigning location.href to the current page reloads forever and
	// leaves a blank WebView (v1.2.27).
	return `(function(){if(window.__csqttOauthProxy)return;window.__csqttOauthProxy=1;var base=` + string(b) + `;var prefix=` + string(prefix) + `;var done=` + string(d) + `;var marker=` + string(marker) + `;var status=` + string(status) + `;function normPath(p){p=String(p||'');if(p.length>1&&p.charAt(p.length-1)==='/')p=p.slice(0,-1);return p;}function pathKey(u){try{var a=document.createElement('a');a.href=u;return normPath(a.pathname)+(a.search||'');}catch(e){return '';}}function alreadyHere(u){try{return pathKey(u)===normPath(location.pathname||'')+(location.search||'');}catch(e){return false;}}function fixBase(){try{var m=String(location.pathname||'').match(/^\/v\/([^\/]+)/);if(!m)return;var want=prefix+m[1]+'/';var b=document.getElementById('base')||document.querySelector('base');if(!b){b=document.createElement('base');b.id='base';(document.head||document.documentElement).insertBefore(b,(document.head||document.documentElement).firstChild);}if(b.getAttribute('href')!==want)b.setAttribute('href',want);}catch(e){}}function preferLogin(){try{var path=String(location.pathname||'');if(/^\/v\/vk\.(ru|com)\/?$/.test(path)){var dest=base+prefix+'m.vk.ru/login';if(!alreadyHere(dest))location.replace(dest);return true;}return false;}catch(e){return false;}}function rootProxy(u){try{if(!u||u.charAt(0)!=='/'||u.charAt(1)==='/')return u;if(u.indexOf(prefix)===0)return u;var m=String(location.pathname||'').match(/^\/v\/([^\/]+)/);if(!m)return u;return prefix+m[1]+u;}catch(e){return u;}}function toProxy(u){try{u=String(u||'');if(u.charAt(0)==='/'&&u.charAt(1)!=='/'){var rp=rootProxy(u);if(rp!==u)return rp;}var a=document.createElement('a');a.href=u;var h=String(a.hostname||'').toLowerCase();if(!h||h==='127.0.0.1'||h==='localhost')return String(u);if(!(/(^|\.)vk\.(com|ru)$/.test(h)||/(^|\.)userapi\.com$/.test(h)||h.indexOf('vk-cdn')>=0||h.indexOf('vkuseraudio')>=0||h.indexOf('vkcc.net')>=0))return String(u);if((h==='vk.ru'||h==='vk.com')&&(!a.pathname||a.pathname==='/')){return base+prefix+'m.'+h+'/login'+(a.search||'')+(a.hash||'');}return base+prefix+h+(a.pathname||'/')+(a.search||'')+(a.hash||'');}catch(e){return String(u);}}function navTo(u,replace){try{var n=toProxy(String(u||''));if(alreadyHere(n))return false;if(replace)location.replace(n);else location.assign(n);return n!==String(u);}catch(e){return false;}}function hoist(){try{if(preferLogin())return;var href=String(location.href||'');if(href.indexOf(marker)>=0)return;if(/^https?:/i.test(href)&&href.indexOf('127.0.0.1')<0&&href.indexOf('localhost')<0){var p=toProxy(href);if(p!==href&&!alreadyHere(p)){location.replace(p);return;}}var h=String(location.hash||'');var s=String(location.search||'');if(h.indexOf('payload=')>=0&&/silent_token/.test(h)){return;}var q='';if(h.indexOf('access_token=')>=0||h.indexOf('error=')>=0){q=h.replace(/^#/,'');}else if(s.indexOf('access_token=')>=0||s.indexOf('error=')>=0){q=s.replace(/^\?/,'');}else{return;}var sep=done.indexOf('?')>=0?'&':'?';location.replace(done+sep+q);}catch(e){}}function pollStatus(){try{if(window.__csqttOauthDone)return;var x=new XMLHttpRequest();x.open('GET',status,true);x.withCredentials=true;x.timeout=10000;x.onload=function(){try{var j=JSON.parse(x.responseText||'{}');if(j&&j.state==='ok'&&j.url){window.__csqttOauthDone=1;location.replace(j.url);}}catch(e){}};x.send();}catch(e){}}function rewriteAttrs(){try{var nodes=document.querySelectorAll('a[href],form[action],link[href],script[src],img[src],iframe[src]');for(var i=0;i<nodes.length;i++){var el=nodes[i];var attr='href';if(el.tagName==='FORM')attr='action';else if(el.tagName==='SCRIPT'||el.tagName==='IMG'||el.tagName==='IFRAME')attr='src';var cur=el.getAttribute(attr);if(!cur)continue;var n=toProxy(cur);if(n!==cur)el.setAttribute(attr,n);}}catch(e){}}function hookLocation(){try{var _as=Location.prototype.assign,_rp=Location.prototype.replace;Location.prototype.assign=function(u){var n=toProxy(String(u));if(alreadyHere(n))return;return _as.call(this,n);};Location.prototype.replace=function(u){var n=toProxy(String(u));if(alreadyHere(n))return;return _rp.call(this,n);};var desc=Object.getOwnPropertyDescriptor(Location.prototype,'href');if(desc&&desc.set&&desc.get){Object.defineProperty(Location.prototype,'href',{configurable:true,enumerable:true,get:function(){return desc.get.call(this);},set:function(v){var n=toProxy(String(v));if(alreadyHere(n))return;desc.set.call(this,n);}});}}catch(e){}try{var _ps=history.pushState,_rs=history.replaceState;history.pushState=function(s,t,u){if(u!=null&&u!==''){var n=toProxy(String(u));if(n!==String(u))u=n;}return _ps.call(this,s,t,u);};history.replaceState=function(s,t,u){if(u!=null&&u!==''){var n=toProxy(String(u));if(n!==String(u))u=n;}return _rs.call(this,s,t,u);};}catch(e){}}document.addEventListener('click',function(e){var t=e.target;while(t&&t.tagName!=='A')t=t.parentNode;if(!t||!t.href)return;var raw=t.getAttribute('href')||t.href;var n=toProxy(raw);if(n!==raw){e.preventDefault();if(!alreadyHere(n))location.assign(n);}},true);document.addEventListener('submit',function(e){try{var f=e.target;if(!f||!f.action)return;var n=toProxy(f.getAttribute('action')||f.action);if(n!==(f.getAttribute('action')||f.action))f.action=n;}catch(err){}},true);function hookNet(){try{var of=window.fetch;if(typeof of==='function'){window.fetch=function(input,init){try{var u=(typeof input==='string')?input:(input&&input.url);if(u){var n=toProxy(String(u));if(n!==String(u)){if(typeof input==='string')input=n;else if(typeof Request!=='undefined')input=new Request(n,input);}}}catch(e){}return of.call(this,input,init);};}}catch(e){}try{var XO=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(){try{if(typeof arguments[1]==='string')arguments[1]=toProxy(arguments[1]);}catch(e){}return XO.apply(this,arguments);};}catch(e){}}hookLocation();hookNet();fixBase();hoist();rewriteAttrs();pollStatus();window.addEventListener('hashchange',hoist);setInterval(function(){fixBase();hoist();rewriteAttrs();pollStatus();},800);})();`
}

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
	"strings"
	"time"
)

// WebView AntiNet резолвит DNS через VPN приложения (не protect модуля) → ERR_NAME_NOT_RESOLVED
// на oauth.vk.com. Весь OAuth идёт на 127.0.0.1; helper ходит на VK через protect + cookie jar.

const (
	vkOAuthProxyPrefix = "/v/"
	vkOAuthStartPath   = "/csqtt-vk-oauth-start"
	vkOAuthProxyMaxBody = 2 << 20
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
)

type vkOAuthProxy struct {
	base   string // http://127.0.0.1:port
	client *http.Client
}

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

func normalizeVkProxyHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	h = strings.ReplaceAll(h, ".vk.ru", ".vk.com")
	if h == "vk.ru" {
		h = "vk.com"
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
		base: base,
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
	// Instant localhost paint, then one authorize URL (mobile only — dual mobile+page triggered 429).
	mux.HandleFunc(vkOAuthStartPath, func(w http.ResponseWriter, r *http.Request) {
		auth := p.authorizeURL("mobile")
		// 302 avoids a second HTML hop; WebView stays on loopback while proxy fetches VK.
		if r.URL.Query().Get("html") != "1" {
			w.Header().Set("Cache-Control", "no-store")
			http.Redirect(w, r, strings.TrimPrefix(auth, p.base), http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		esc := html.EscapeString(auth)
		_, _ = io.WriteString(w, `<!DOCTYPE html><html><head><meta charset="utf-8">`+
			`<meta http-equiv="refresh" content="0;url=`+esc+`">`+
			`<title>CSQTT VK</title></head>`+
			`<body style="font-family:sans-serif;padding:24px;background:#111;color:#eee">`+
			`<p>Загрузка входа VK… Не закрывайте окно до редиректа после входа.</p>`+
			`<script>location.replace(`+mustJSON(auth)+`);</script>`+
			`<p><a style="color:#8cf" href="`+esc+`">Продолжить</a></p></body></html>`)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/" || path == "" {
			http.Redirect(w, r, vkOAuthStartPath, http.StatusFound)
			return
		}
		if strings.HasPrefix(path, vkOAuthProxyPrefix) {
			p.serve(w, r)
			return
		}
		http.NotFound(w, r)
	})

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 15 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	stop = func() {
		_ = srv.Close()
		_ = ln.Close()
	}

	startURLs = []string{base + vkOAuthStartPath}
	return startURLs, doneURL, stop, nil
}

func mustJSON(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}

func (p *vkOAuthProxy) authorizeURL(display string) string {
	redirect := url.QueryEscape("https://oauth.vk.com/blank.html")
	return fmt.Sprintf("%s%soauth.vk.com/authorize?client_id=7793118&scope=1073737727&redirect_uri=%s&display=%s&response_type=token&revoke=1&v=5.199",
		p.base, vkOAuthProxyPrefix, redirect, display)
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
			return sub[1] + sub[2] + prefix + sub[3] + sub[4]
		})
		body = reRootRelCSS.ReplaceAllStringFunc(body, func(m string) string {
			sub := reRootRelCSS.FindStringSubmatch(m)
			if len(sub) != 5 || strings.HasPrefix(sub[3], "//") {
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
		return "https://" + normalizeVkProxyHost(host) + loc
	}
	if strings.Contains(loc, "://") {
		return loc
	}
	return "https://" + normalizeVkProxyHost(host) + "/" + strings.TrimPrefix(loc, "./")
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

func (p *vkOAuthProxy) serve(w http.ResponseWriter, r *http.Request) {
	host, path, ok := parseVkProxyPath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	up := &url.URL{
		Scheme:   "https",
		Host:     host,
		Path:     path,
		RawQuery: r.URL.RawQuery,
	}
	retrySelf := r.URL.RequestURI()
	if !strings.HasPrefix(retrySelf, "/") {
		retrySelf = vkOAuthStartPath
	}

	var bodyBytes []byte
	if r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
		bodyBytes, _ = io.ReadAll(io.LimitReader(r.Body, vkOAuthProxyMaxBody))
		_ = r.Body.Close()
	}

	started := time.Now()
	var resp *http.Response
	var lastErr error
	got429 := false
	const maxAttempts = 3
	for attempt := 1; attempt <= maxAttempts; attempt++ {
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
			req.Header.Set("Referer", p.unrewriteURL(ref))
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			req.Header.Set("Origin", p.unrewriteURL(origin))
		}
		req.Host = host
		if len(bodyBytes) > 0 {
			req.ContentLength = int64(len(bodyBytes))
		}

		resp, lastErr = p.client.Do(req)
		got429 = lastErr == nil && resp != nil && resp.StatusCode == http.StatusTooManyRequests
		if lastErr == nil && resp != nil && !got429 {
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
			attempt, maxAttempts, r.Method, up.Host+up.Path, status, lastErr, time.Since(started).Round(time.Millisecond))
		if attempt < maxAttempts {
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
	if got429 || resp == nil {
		emitLog("CSQTT OAuth proxy: 429 %s %s after %s", r.Method, up.Host+up.Path, time.Since(started).Round(time.Millisecond))
		p.writeRetryPage(w, "Слишком много запросов к VK",
			"Upstream вернул 429 (rate limit). Подождите и повторите — не закрывайте окно до входа.",
			retrySelf, 8)
		return
	}
	defer resp.Body.Close()
	emitLog("CSQTT OAuth proxy: OK %s %s → %d (%s)", r.Method, up.Host+up.Path, resp.StatusCode, time.Since(started).Round(time.Millisecond))

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
		p.writeRetryPage(w, "Слишком много запросов к VK",
			"Страница rate-limit от промежуточного узла. Подождите и нажмите «Повторить».",
			retrySelf, 8)
		return
	}
	out := p.rewriteHTML(bodyStr, host)
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
	return `(function(){if(window.__csqttOauthProxy)return;window.__csqttOauthProxy=1;var base=` + string(b) + `;var prefix=` + string(prefix) + `;var done=` + string(d) + `;var marker=` + string(marker) + `;function rootProxy(u){try{if(!u||u.charAt(0)!=='/'||u.charAt(1)==='/')return u;var m=String(location.pathname||'').match(/^\/v\/([^\/]+)/);if(!m)return u;return prefix+m[1]+u;}catch(e){return u;}}function toProxy(u){try{u=String(u||'');if(u.charAt(0)==='/'&&u.charAt(1)!=='/'){var rp=rootProxy(u);if(rp!==u)return rp;}var a=document.createElement('a');a.href=u;var h=String(a.hostname||'').toLowerCase();if(!h||h==='127.0.0.1'||h==='localhost')return String(u);if(!(/(^|\.)vk\.(com|ru)$/.test(h)||/(^|\.)userapi\.com$/.test(h)||h.indexOf('vk-cdn')>=0||h.indexOf('vkuseraudio')>=0||h.indexOf('vkcc.net')>=0))return String(u);h=h.replace(/\.vk\.ru$/i,'.vk.com').replace(/^vk\.ru$/i,'vk.com');return base+prefix+h+(a.pathname||'/')+(a.search||'')+(a.hash||'');}catch(e){return String(u);}}function hoist(){try{var href=String(location.href||'');if(href.indexOf(marker)>=0)return;if(/^https?:/i.test(href)&&href.indexOf('127.0.0.1')<0&&href.indexOf('localhost')<0){var p=toProxy(href);if(p!==href){location.replace(p);return;}}var h=String(location.hash||'');var s=String(location.search||'');if(h.indexOf('payload=')>=0&&/silent_token/.test(h)){location.replace(base+prefix+'oauth.vk.com/authorize?client_id=7793118&scope=1073737727&redirect_uri='+encodeURIComponent('https://oauth.vk.com/blank.html')+'&display=mobile&response_type=token&revoke=1&v=5.199');return;}var q='';if(h.indexOf('access_token=')>=0||h.indexOf('error=')>=0){q=h.replace(/^#/,'');}else if(s.indexOf('access_token=')>=0||s.indexOf('error=')>=0){q=s.replace(/^\?/,'');}else{return;}var sep=done.indexOf('?')>=0?'&':'?';location.replace(done+sep+q);}catch(e){}}function rewriteAttrs(){try{var nodes=document.querySelectorAll('a[href],form[action],link[href],script[src],img[src],iframe[src]');for(var i=0;i<nodes.length;i++){var el=nodes[i];var attr='href';if(el.tagName==='FORM')attr='action';else if(el.tagName==='SCRIPT'||el.tagName==='IMG'||el.tagName==='IFRAME')attr='src';var cur=el.getAttribute(attr);if(!cur)continue;var n=toProxy(cur);if(n!==cur)el.setAttribute(attr,n);}}catch(e){}}document.addEventListener('click',function(e){var t=e.target;while(t&&t.tagName!=='A')t=t.parentNode;if(!t||!t.href)return;var n=toProxy(t.getAttribute('href')||t.href);if(n!==(t.getAttribute('href')||t.href)){e.preventDefault();location.href=n;}},true);document.addEventListener('submit',function(e){try{var f=e.target;if(!f||!f.action)return;var n=toProxy(f.getAttribute('action')||f.action);if(n!==(f.getAttribute('action')||f.action))f.action=n;}catch(err){}},true);hoist();rewriteAttrs();window.addEventListener('hashchange',hoist);setInterval(function(){hoist();rewriteAttrs();},250);})();`
}

package main

import (
	"encoding/json"
	"fmt"
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
	vkOAuthProxyMaxBody = 2 << 20
)

var (
	reAbsVKURL = regexp.MustCompile(`(?i)(https?:)?//((?:[a-z0-9-]+\.)*(?:vk\.(?:com|ru)|userapi\.com|vkuseraudio\.net|vk-cdn\.net|vkcc\.net))(/[^"'>\s]*)?`)
	reHostAttr = regexp.MustCompile(`(?i)(https://|http://|//)((?:[a-z0-9-]+\.)*(?:vk\.(?:com|ru)|userapi\.com|vkuseraudio\.net|vk-cdn\.net|vkcc\.net))`)
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
	transport := http.DefaultTransport
	if vkHTTP != nil && vkHTTP.Transport != nil {
		transport = vkHTTP.Transport
	}
	p := &vkOAuthProxy{
		base: base,
		client: &http.Client{
			Timeout:   60 * time.Second,
			Jar:       jar,
			Transport: transport,
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
			`<body><p>Авторизация VK… окно закроется автоматически.</p></body></html>`)
	})
	mux.HandleFunc(vkOAuthProxyPrefix, p.serve)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, vkOAuthProxyPrefix) {
			p.serve(w, r)
			return
		}
		http.NotFound(w, r)
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	stop = func() {
		_ = srv.Close()
		_ = ln.Close()
	}

	startURLs = []string{
		p.authorizeURL("mobile"),
		p.authorizeURL("page"),
	}
	return startURLs, doneURL, stop, nil
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

func (p *vkOAuthProxy) rewriteHTML(body string) string {
	body = reAbsVKURL.ReplaceAllStringFunc(body, func(m string) string {
		return p.rewriteAbsoluteURL(m)
	})
	body = reHostAttr.ReplaceAllStringFunc(body, func(m string) string {
		return p.rewriteAbsoluteURL(m)
	})
	return body
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
	var body io.Reader
	if r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
		body = r.Body
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, up.String(), body)
	if err != nil {
		http.Error(w, "bad upstream request", http.StatusBadGateway)
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

	resp, err := p.client.Do(req)
	if err != nil {
		http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	rewriteBody := strings.Contains(ct, "text/html") || strings.Contains(ct, "javascript") || strings.Contains(ct, "json") || strings.Contains(ct, "text/css")

	for k, vv := range resp.Header {
		lk := strings.ToLower(k)
		if lk == "content-length" || lk == "content-encoding" || lk == "transfer-encoding" || lk == "set-cookie" {
			continue
		}
		if lk == "location" {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		w.Header().Set("Location", p.rewriteLocation(loc))
	}
	w.Header().Set("Cache-Control", "no-store")

	if !rewriteBody {
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, io.LimitReader(resp.Body, vkOAuthProxyMaxBody*4))
		return
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, vkOAuthProxyMaxBody))
	if err != nil {
		http.Error(w, "upstream read", http.StatusBadGateway)
		return
	}
	out := p.rewriteHTML(string(raw))
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
	return `(function(){if(window.__csqttOauthProxy)return;window.__csqttOauthProxy=1;var base=` + string(b) + `;var prefix=` + string(prefix) + `;var done=` + string(d) + `;var marker=` + string(marker) + `;function toProxy(u){try{var a=document.createElement('a');a.href=u;var h=String(a.hostname||'').toLowerCase();if(!h||h==='127.0.0.1'||h==='localhost')return String(u);if(!(/(^|\.)vk\.(com|ru)$/.test(h)||/(^|\.)userapi\.com$/.test(h)||h.indexOf('vk-cdn')>=0||h.indexOf('vkuseraudio')>=0||h.indexOf('vkcc.net')>=0))return String(u);h=h.replace(/\.vk\.ru$/i,'.vk.com').replace(/^vk\.ru$/i,'vk.com');return base+prefix+h+(a.pathname||'/')+(a.search||'')+(a.hash||'');}catch(e){return String(u);}}function hoist(){try{var href=String(location.href||'');if(href.indexOf(marker)>=0)return;if(/^https?:/i.test(href)&&href.indexOf('127.0.0.1')<0&&href.indexOf('localhost')<0){var p=toProxy(href);if(p!==href){location.replace(p);return;}}var h=String(location.hash||'');var s=String(location.search||'');if(h.indexOf('payload=')>=0&&/silent_token/.test(h)){location.replace(base+prefix+'oauth.vk.com/authorize?client_id=7793118&scope=1073737727&redirect_uri='+encodeURIComponent('https://oauth.vk.com/blank.html')+'&display=mobile&response_type=token&revoke=1&v=5.199');return;}var q='';if(h.indexOf('access_token=')>=0||h.indexOf('error=')>=0){q=h.replace(/^#/,'');}else if(s.indexOf('access_token=')>=0||s.indexOf('error=')>=0){q=s.replace(/^\?/,'');}else{return;}var sep=done.indexOf('?')>=0?'&':'?';location.replace(done+sep+q);}catch(e){}}function rewriteAttrs(){try{var nodes=document.querySelectorAll('a[href],form[action],link[href],script[src],img[src],iframe[src]');for(var i=0;i<nodes.length;i++){var el=nodes[i];var attr='href';if(el.tagName==='FORM')attr='action';else if(el.tagName==='SCRIPT'||el.tagName==='IMG'||el.tagName==='IFRAME')attr='src';var cur=el.getAttribute(attr);if(!cur)continue;var n=toProxy(cur);if(n!==cur)el.setAttribute(attr,n);}}catch(e){}}document.addEventListener('click',function(e){var t=e.target;while(t&&t.tagName!=='A')t=t.parentNode;if(!t||!t.href)return;var n=toProxy(t.href);if(n!==t.href){e.preventDefault();location.href=n;}},true);document.addEventListener('submit',function(e){try{var f=e.target;if(!f||!f.action)return;var n=toProxy(f.action);if(n!==f.action)f.action=n;}catch(err){}},true);hoist();rewriteAttrs();window.addEventListener('hashchange',hoist);setInterval(function(){hoist();rewriteAttrs();},250);})();`
}

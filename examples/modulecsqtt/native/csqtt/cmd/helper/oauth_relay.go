package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

// Локальный callback: VK implicit OAuth отдаёт access_token во fragment на oauth.vk.com/blank.html,
// а AntiNet в navigation-режиме часто не видит hash. injectJs перенаправляет на loopback с token в query.
const vkOAuthCallbackPath = "/csqtt-vk-oauth-done"

func startVkOAuthCallbackServer() (doneURL string, stop func(), err error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	doneURL = fmt.Sprintf("http://127.0.0.1:%d%s", port, vkOAuthCallbackPath)

	mux := http.NewServeMux()
	mux.HandleFunc(vkOAuthCallbackPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, `<!DOCTYPE html><html><head><meta charset="utf-8"><title>CSQTT</title></head>`+
			`<body><p>Авторизация VK… окно закроется автоматически.</p></body></html>`)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()

	stop = func() {
		_ = srv.Close()
		_ = ln.Close()
	}
	return doneURL, stop, nil
}

func vkOAuthCallbackPattern() string {
	return vkOAuthCallbackPath
}

func vkOAuthDoneURLForTest(port int) string {
	return fmt.Sprintf("http://127.0.0.1:%d%s", port, vkOAuthCallbackPath)
}

func parseVkAccessTokenFromCallbackURL(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if i := strings.Index(s, vkOAuthCallbackPath); i >= 0 {
		s = s[i:]
	}
	return parseVkAccessToken(s)
}

// WebView OAuth рисует AntiNet (не helper): DNS идёт через VPN приложения, не через protect модуля.
func vkDomainComShimJS() string {
	return `(function(){if(window.__csqttVkCom)return;window.__csqttVkCom=1;function fix(){try{var u=String(location.href||'');if(u.indexOf('127.0.0.1')>=0||u.indexOf('localhost')>=0)return;if(/\.vk\.ru(\/|:|$)/i.test(u)||u.indexOf('://vk.ru/')>=0||u.indexOf('://vk.ru?')>=0){location.replace(u.replace(/\.vk\.ru/gi,'.vk.com').replace(/:\/\/vk\.ru/gi,'://vk.com'));}}catch(e){}}fix();window.addEventListener('hashchange',fix);setInterval(fix,400);})();`
}

func vkOAuthInjectJS(callbackURL string) string {
	return vkDomainComShimJS() + vkOAuthHoistJS(callbackURL)
}

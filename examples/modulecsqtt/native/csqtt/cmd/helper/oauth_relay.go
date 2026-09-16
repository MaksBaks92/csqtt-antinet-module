package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

// Локальный callback: VK implicit OAuth отдаёт access_token во fragment;
// injectJs перенаправляет на loopback с token в query (AntiNet navigation часто не видит hash).
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

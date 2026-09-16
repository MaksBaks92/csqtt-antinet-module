package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
)

// Ручной ввод хешей не требует грузить m.vk.ru (часто не резолвится в WebView под VPN).
const (
	hashFormPagePath = "/csqtt-hash-form"
	hashFormDonePath = "/csqtt-hashes-done"
)

func startManualHashFormServer() (pageURL, doneURL string, stop func(), err error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", "", nil, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	pageURL = fmt.Sprintf("http://127.0.0.1:%d%s", port, hashFormPagePath)
	doneURL = fmt.Sprintf("http://127.0.0.1:%d%s", port, hashFormDonePath)

	serve := func(w http.ResponseWriter, title string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>`+title+`</title></head><body></body></html>`)
	}
	mux := http.NewServeMux()
	mux.HandleFunc(hashFormPagePath, func(w http.ResponseWriter, r *http.Request) { serve(w, "CSQTT") })
	mux.HandleFunc(hashFormDonePath, func(w http.ResponseWriter, r *http.Request) { serve(w, "CSQTT") })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	stop = func() {
		_ = srv.Close()
		_ = ln.Close()
	}
	return pageURL, doneURL, stop, nil
}

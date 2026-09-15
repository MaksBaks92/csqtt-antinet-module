// SPDX-License-Identifier: MIT
//
// CSQTT helper — протокол-модуль AntiNet. Каноны shared/* инжектит build.py.
// Data-plane: SOCKS5 → gVisor → UDP 127.0.0.1 → rust CSQTT engine (TURN/RTP).
// Движок — производный от https://github.com/amurcanov/csqtt (PolyForm-Noncommercial-1.0.0).
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"csqtt-antinet/tunnel"

	_ "golang.org/x/net/dns/dnsmessage" // канон shared/dns, инжектируется build.py
)

const (
	linkScheme      = "csqtt"
	linkHostConnect = "connect"
	defaultDialSec  = 20
	readyWaitBudget = 90 * time.Second
)

type csqttStrings struct {
	badLinkFmt           string
	missingHashes        string
	engineLoadFailedFmt  string
	engineStartFailedFmt string
	engineNotReadyFmt    string
	badTunIPFmt          string
	packetPortFailed     string
	bridgeListenFailed   string
	socksListenFailedFmt string
	writeReadyFailedFmt  string
	socksUpFmt           string
	openingEngine        string
	handoverLog          string
}

var csqttStringsRU = csqttStrings{
	badLinkFmt:           "CSQTT: неверная ссылка: %v",
	missingHashes:        "CSQTT: в ссылке нет hashes=, укажите VK-хеши в настройках модуля",
	engineLoadFailedFmt:  "CSQTT: не удалось загрузить движок: %v",
	engineStartFailedFmt: "CSQTT: движок не стартовал: %v",
	engineNotReadyFmt:    "CSQTT: туннель не поднялся за %s",
	badTunIPFmt:          "CSQTT: некорректный TUN IP %q",
	packetPortFailed:     "CSQTT: движок не открыл пакетный UDP-порт",
	bridgeListenFailed:   "CSQTT: не удалось открыть пакетный мост",
	socksListenFailedFmt: "CSQTT: не удалось взять SOCKS-листенер: %v",
	writeReadyFailedFmt:  "CSQTT: не удалось записать маркер готовности: %v",
	socksUpFmt:           "CSQTT: SOCKS5 поднят на 127.0.0.1:%d",
	openingEngine:        "CSQTT: поднимаю TURN-туннель",
	handoverLog:          "хендовер: сменилась сеть — TURN-воркеры переподключатся сами",
}

var csqttStringsEN = csqttStrings{
	badLinkFmt:           "CSQTT: bad link: %v",
	missingHashes:        "CSQTT: link has no hashes=; set VK hashes in module settings",
	engineLoadFailedFmt:  "CSQTT: failed to load engine: %v",
	engineStartFailedFmt: "CSQTT: engine failed to start: %v",
	engineNotReadyFmt:    "CSQTT: tunnel did not come up within %s",
	badTunIPFmt:          "CSQTT: bad TUN IP %q",
	packetPortFailed:     "CSQTT: engine did not open a packet UDP port",
	bridgeListenFailed:   "CSQTT: packet bridge listen failed",
	socksListenFailedFmt: "CSQTT: SOCKS listener failed: %v",
	writeReadyFailedFmt:  "CSQTT: failed to mark readiness: %v",
	socksUpFmt:           "CSQTT: SOCKS5 up on 127.0.0.1:%d",
	openingEngine:        "CSQTT: starting TURN tunnel",
	handoverLog:          "handover: network changed, TURN workers will reconnect",
}

func csqttStringsFor(lang string) csqttStrings {
	if strings.EqualFold(strings.TrimSpace(lang), "ru") {
		return csqttStringsRU
	}
	return csqttStringsEN
}

type csqttLink struct {
	Host     string
	Peer     string
	Password string
	Hashes   []string
	Name     string
}

func (l csqttLink) peerAddr() string {
	peer := strings.TrimSpace(l.Peer)
	host := strings.TrimSpace(l.Host)
	if strings.Contains(peer, ":") {
		return peer
	}
	if host == "" {
		return peer
	}
	if peer == "" {
		return host
	}
	return net.JoinHostPort(host, peer)
}

func (l csqttLink) server() string {
	if addr := l.peerAddr(); addr != "" {
		return addr
	}
	return "csqtt"
}

func (l csqttLink) displayName() string {
	if l.Name != "" {
		return l.Name
	}
	if host := strings.TrimSpace(l.Host); host != "" {
		return "CSQTT " + host
	}
	return "CSQTT"
}

func parseCsqttLink(raw string) (csqttLink, error) {
	var l csqttLink
	s := strings.TrimSpace(raw)
	if s == "" {
		return l, fmt.Errorf("empty link")
	}
	u, err := url.Parse(s)
	if err != nil {
		return l, fmt.Errorf("parse %q: %w", s, err)
	}
	if !strings.EqualFold(u.Scheme, linkScheme) {
		return l, fmt.Errorf("not a %s:// link", linkScheme)
	}
	l.Name = strings.TrimSpace(u.Fragment)
	host := strings.ToLower(strings.TrimSpace(u.Host))
	if host == linkHostConnect || u.Host == "" && strings.EqualFold(strings.Trim(u.Path, "/"), linkHostConnect) {
		q := u.Query()
		l.Host = strings.TrimSpace(q.Get("host"))
		l.Peer = strings.TrimSpace(q.Get("peer"))
		l.Password = strings.TrimSpace(q.Get("password"))
		l.Hashes = splitHashes(q.Get("hashes"))
		if l.Password == "" {
			return l, fmt.Errorf("connect: missing password=")
		}
		if l.Host == "" && l.Peer == "" {
			return l, fmt.Errorf("connect: missing host=/peer=")
		}
		return l, nil
	}
	if u.User != nil {
		if p, ok := u.User.Password(); ok {
			l.Password = p
			if u.User.Username() != "" {
				l.Host = u.User.Username()
			}
		} else {
			l.Password = u.User.Username()
		}
	}
	if h := strings.TrimSpace(u.Host); h != "" {
		l.Peer = h
		if hostOnly, _, err := net.SplitHostPort(h); err == nil {
			l.Host = hostOnly
		} else {
			l.Host = h
		}
	}
	if extra := u.Query().Get("hashes"); extra != "" {
		l.Hashes = splitHashes(extra)
	}
	if l.Password == "" || l.peerAddr() == "" {
		return l, fmt.Errorf("legacy link needs password@host:port")
	}
	return l, nil
}

func splitHashes(raw string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == '+' || r == ',' || r == ' ' || r == '\t' || r == '\n'
	}) {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func normalizeCsqtt(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || strings.HasPrefix(strings.ToLower(s), linkScheme+"://") {
		return ""
	}
	if !strings.HasPrefix(s, "{") {
		return ""
	}
	var m map[string]any
	if json.Unmarshal([]byte(s), &m) != nil {
		return ""
	}
	str := func(k string) string {
		v, _ := m[k].(string)
		return strings.TrimSpace(v)
	}
	password := str("password")
	host := str("host")
	peer := str("peer")
	if password == "" || (host == "" && peer == "") {
		return ""
	}
	q := url.Values{}
	q.Set("v", "2")
	if host != "" {
		q.Set("host", host)
	}
	if peer != "" {
		q.Set("peer", peer)
	}
	q.Set("password", password)
	if h := str("hashes"); h != "" {
		q.Set("hashes", strings.Join(splitHashes(h), " "))
	}
	link := linkScheme + "://" + linkHostConnect + "?" + q.Encode()
	if n := str("name"); n != "" {
		link += "#" + url.PathEscape(n)
	}
	return link
}

func moduleCall(verb, arg string) string {
	switch verb {
	case "summarize":
		l, err := parseCsqttLink(arg)
		if err != nil {
			return "\n"
		}
		return l.displayName() + "\n" + l.server()
	case "normalize":
		return normalizeCsqtt(arg)
	}
	return ""
}

func realMain(configContent, resolversPath, profileDir, protectPath string, listenFd int) int {
	_ = resolversPath
	startHostEventReader()
	dieWithParent()
	protectFromOomKill()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	cfg := parseConfig(configContent)
	s := csqttStringsFor(cfg["APP_LANG"])
	port, _ := strconv.Atoi(cfg["LISTEN_PORT"])
	user := cfg["SOCKS_USER"]
	pass := cfg["SOCKS_PASS"]
	debug := cfg["SETTING_debugLog"] == "true"

	link, err := parseCsqttLink(cfg["LINK"])
	if err != nil {
		emitLog(s.badLinkFmt, err)
		emitStatus(statusFatal, "bad link")
		log.Fatalf("parse LINK: %v", err)
	}
	hashes := link.Hashes
	if len(hashes) == 0 {
		hashes = splitHashes(cfg["SETTING_vkHashes"])
	}
	if len(hashes) == 0 {
		emitLog(s.missingHashes)
		emitStatus(statusFatal, "missing vk hashes")
		log.Fatalf("missing vk hashes")
	}

	dialTimeout := settingDuration(cfg, "SETTING_dialTimeoutSec", defaultDialSec)
	workers, _ := strconv.Atoi(strings.TrimSpace(cfg["SETTING_workers"]))
	obfs := strings.TrimSpace(cfg["SETTING_obfs"])
	turnTransport := strings.TrimSpace(cfg["SETTING_turnTransport"])

	resolver := newProtectedResolver(cfg["DNS_SERVERS"], protectPath)

	search := []string{profileDir}
	if profileDir != "" {
		search = append(search, filepath.Dir(profileDir), filepath.Dir(filepath.Dir(profileDir)))
	}
	if err := engineLoad(search...); err != nil {
		emitLog(s.engineLoadFailedFmt, err)
		emitStatus(statusFatal, "engine load failed")
		log.Fatalf("engine load: %v", err)
	}

	protectFn := protectFdFunc(protectPath)
	engineSetProtect(func(fd int64) bool {
		if protectFn == nil {
			return true
		}
		return protectFn(int32(fd))
	})

	engineCfg, _ := json.Marshal(map[string]any{
		"peer":           link.peerAddr(),
		"password":       link.Password,
		"hashes":         strings.Join(hashes, ","),
		"workers":        workers,
		"device_id":      "antinet",
		"captcha_mode":   "auto",
		"obfs":           obfs,
		"turn_transport": turnTransport,
		"fingerprint":    "firefox",
	})

	emitProgress(s.openingEngine)
	if err := engineStart(string(engineCfg)); err != nil {
		emitLog(s.engineStartFailedFmt, err)
		emitStatus(statusFatal, "engine start failed")
		log.Fatalf("engine start: %v", err)
	}
	defer engineStop()

	if err := engineWaitReady(int(readyWaitBudget / time.Millisecond)); err != nil {
		emitLog(s.engineNotReadyFmt, readyWaitBudget)
		emitStatus(statusFatal, "engine not ready")
		log.Fatalf("engine wait: %v", err)
	}

	tunIP := net.ParseIP(strings.TrimSpace(engineTunIP()))
	if tunIP == nil || tunIP.To4() == nil {
		emitLog(s.badTunIPFmt, engineTunIP())
		emitStatus(statusFatal, "bad tun ip")
		log.Fatalf("bad TUN IP %q", engineTunIP())
	}
	pktPort := enginePacketPort()
	if pktPort <= 0 || pktPort > 65535 {
		emitLog(s.packetPortFailed)
		emitStatus(statusFatal, "no packet port")
		log.Fatalf("packet port %d", pktPort)
	}
	engineAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: pktPort}

	bridge, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		emitLog(s.bridgeListenFailed)
		emitStatus(statusFatal, "packet bridge failed")
		log.Fatalf("packet bridge: %v", err)
	}
	defer bridge.Close()

	tun, err := tunnel.NewIPTunnel(tunIP, func(pkt []byte) {
		if _, werr := bridge.WriteToUDP(pkt, engineAddr); werr != nil && debug {
			log.Printf("[BRIDGE] write: %v", werr)
		}
	})
	if err != nil {
		emitStatus(statusFatal, "netstack failed")
		log.Fatalf("netstack: %v", err)
	}
	defer tun.Close()

	go func() {
		buf := make([]byte, 65535)
		for {
			n, _, rerr := bridge.ReadFromUDP(buf)
			if rerr != nil {
				return
			}
			if n > 0 {
				tun.InjectInbound(buf[:n])
			}
		}
	}()
	// First outbound datagram teaches the rust engine our UDP source address.

	ln, err := openListener(port, listenFd)
	if err != nil {
		emitLog(s.socksListenFailedFmt, err)
		emitStatus(statusFatal, "socks listen failed")
		log.Fatalf("listen 127.0.0.1:%d: %v", port, err)
	}
	actualPort := ln.Addr().(*net.TCPAddr).Port
	if err := writeReady(profileDir, actualPort); err != nil {
		emitLog(s.writeReadyFailedFmt, err)
		emitStatus(statusFatal, "write ready marker failed")
		log.Fatalf("write ready marker: %v", err)
	}
	emitProgress(s.socksUpFmt, actualPort)
	emitStatus(statusOK, "")
	log.Printf("csqtt helper: SOCKS5 on 127.0.0.1:%d tun=%s dns=%s pkt=%d", actualPort, tunIP, engineTunDNS(), pktPort)

	setHostEventHandler(func(event string) {
		switch event {
		case "handover", "netlost", "netback", "stall":
			emitLog(s.handoverLog)
		}
	})

	udpT := csqttUDPTransport{tun: tun, resolver: resolver}
	serveSocksListener(ln, func(c net.Conn) {
		handleConn(c, user, pass, tun, resolver, udpT, dialTimeout)
	})
	return 0
}

type csqttUDPTransport struct {
	tun      *tunnel.IPTunnel
	resolver *protectedResolver
}

func (t csqttUDPTransport) LookupHost(host string) ([]string, error) {
	return t.resolver.LookupHost(host)
}

func (t csqttUDPTransport) DialUDPTarget(dst netip.AddrPort) (net.Conn, error) {
	if !dst.Addr().Is4() && !dst.Addr().Is4In6() {
		return nil, errSocksTargetUnreachable
	}
	return t.tun.DialUDP(dst)
}

func settingDuration(cfg map[string]string, key string, defSec int) time.Duration {
	if v, err := strconv.Atoi(strings.TrimSpace(cfg[key])); err == nil && v > 0 {
		return time.Duration(v) * time.Second
	}
	return time.Duration(defSec) * time.Second
}

func handleConn(c net.Conn, user, pass string, tun *tunnel.IPTunnel, resolver *protectedResolver, udpT csqttUDPTransport, dialTimeout time.Duration) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, ok := socksHandshake(c, br, user, pass)
	if !ok {
		return
	}
	if req.Cmd == socksCmdUDPAssociate {
		serveSocksUDPAssociate(c, br, udpT)
		return
	}

	host := req.TargetLabel()
	target := net.JoinHostPort(host, strconv.Itoa(int(req.Port)))
	dialStart := time.Now()
	ip, rerr := resolveV4(req, resolver)
	if rerr != nil {
		log.Printf("[SOCKS] resolve FAILED host=%s err=%v", host, rerr)
		_, _ = c.Write(socksRep(0x04))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	up, err := tun.DialTCP(ctx, ip, req.Port)
	cancel()
	if err != nil {
		log.Printf("[SOCKS] tunnel dial FAILED target=%s ip=%s elapsed=%v err=%v", target, ip, time.Since(dialStart), err)
		_, _ = c.Write(socksRep(0x01))
		return
	}
	defer up.Close()
	if _, err := c.Write(socksRep(0x00)); err != nil {
		return
	}
	relayBidi(c, br, up, target, dialStart)
}

func resolveV4(req socksRequest, resolver *protectedResolver) (string, error) {
	if req.IsIP() {
		if !req.IP.Is4() && !req.IP.Is4In6() {
			return "", fmt.Errorf("IPv6 target %v: tunnel is IPv4-only", req.IP)
		}
		return req.IP.Unmap().String(), nil
	}
	ips, err := resolver.LookupHost(req.Host)
	if err != nil {
		return "", err
	}
	for _, s := range ips {
		if a := net.ParseIP(s); a != nil && a.To4() != nil {
			return a.To4().String(), nil
		}
	}
	return "", fmt.Errorf("no IPv4 address for %s (got %v)", req.Host, ips)
}

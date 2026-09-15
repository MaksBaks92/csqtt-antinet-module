// SPDX-License-Identifier: MIT
//
// CSQTT helper — протокол-модуль AntiNet. Каноны shared/* инжектит build.py.
// Data-plane: SOCKS5 → gVisor → UDP 127.0.0.1 → rust CSQTT engine (TURN/RTP).
// Движок — производный от https://github.com/amurcanov/csqtt (PolyForm-Noncommercial-1.0.0).
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"net/url"
	"os"
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
	vkOAuthTimeout  = 5 * time.Minute
	vkOAuthURL      = "https://oauth.vk.ru/authorize?client_id=7793118&scope=1073737727&redirect_uri=https%3A%2F%2Foauth.vk.ru%2Fblank.html&display=mobile&response_type=token&revoke=1&v=5.199"
	vkOAuthURLCom   = "https://oauth.vk.com/authorize?client_id=7793118&scope=1073737727&redirect_uri=https%3A%2F%2Foauth.vk.ru%2Fblank.html&display=mobile&response_type=token&revoke=1&v=5.199"
	// VK отдаёт implicit-токен в location.hash. Android WebView часто не включает fragment
	// в URL колбэка хоста — param=access_token тогда пустой, юзер видит blank.html и закрывает
	// окно → CANCELLED. JS читает hash и переписывает его в query, который хост уже умеет.
	vkOAuthHoistJS = `(function(){if(window.__csqttOauthHoist)return;window.__csqttOauthHoist=1;function hoist(){try{var h=String(location.hash||'');if(h.indexOf('access_token=')<0)return;var q=h.replace(/^#/,'');if(String(location.search||'').indexOf('access_token=')>=0)return;location.replace(location.protocol+'//'+location.host+location.pathname+'?'+q);}catch(e){}}hoist();setInterval(hoist,250);})();`
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
	vkLoginProgress      string
	vkLoginFailedFmt     string
	vkLoginFallbackFmt   string
	vkUsingLinkHashes    string
	vkAutoAPIProgress    string
	vkAutoAPIFailedFmt   string
	handoverLog          string
}

var csqttStringsRU = csqttStrings{
	badLinkFmt:           "CSQTT: неверная ссылка: %v",
	missingHashes:        "CSQTT: в ссылке нет hashes=, укажите VK-хеши в настройках или включите авто-режим",
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
	vkLoginProgress:      "CSQTT: войдите в VK и подтвердите доступ; окно закроется само",
	vkLoginFailedFmt:     "CSQTT: не удалось получить VK-токен: %v",
	vkLoginFallbackFmt:   "CSQTT: вход в VK не удался (%v), беру хеши из ссылки/настроек",
	vkUsingLinkHashes:    "CSQTT: в ссылке уже есть хеши — вход в VK пропускаю",
	vkAutoAPIProgress:    "CSQTT: создаю звонки VK через API",
	vkAutoAPIFailedFmt:   "CSQTT: не удалось создать звонки VK: %v",
	handoverLog:          "хендовер: сменилась сеть — TURN-воркеры переподключатся сами",
}

var csqttStringsEN = csqttStrings{
	badLinkFmt:           "CSQTT: bad link: %v",
	missingHashes:        "CSQTT: link has no hashes=; set VK hashes in settings or enable auto mode",
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
	vkLoginProgress:      "CSQTT: sign in to VK and allow access; the window closes itself",
	vkLoginFailedFmt:     "CSQTT: failed to get VK token: %v",
	vkLoginFallbackFmt:   "CSQTT: VK login failed (%v), using hashes from link/settings",
	vkUsingLinkHashes:    "CSQTT: link already has hashes, skipping VK login",
	vkAutoAPIProgress:    "CSQTT: creating VK calls via API",
	vkAutoAPIFailedFmt:   "CSQTT: failed to create VK calls: %v",
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
	case "canping":
		return canPingCSQTT(arg)
	}
	return ""
}

func canPingCSQTT(arg string) string {
	lines := strings.SplitN(arg, "\n", 3)
	link := ""
	blob := ""
	if len(lines) > 0 {
		link = strings.TrimSpace(lines[0])
	}
	if len(lines) > 2 {
		blob = lines[2]
	}
	if l, err := parseCsqttLink(link); err == nil && len(l.Hashes) > 0 {
		return "ok"
	}
	if restoreSavedState(blob).VKToken != "" {
		return "ok"
	}
	return "no"
}

func realMain(configContent, resolversPath, profileDir, protectPath string, listenFd int) int {
	_ = resolversPath
	startHostEventReader()
	dieWithParent()
	protectFromOomKill()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	cfg := parseConfig(configContent)
	s := csqttStringsFor(cfg["APP_LANG"])
	configureVkHTTP(protectPath)
	persisted = restoreSavedState(cfg["MODULE_STATE"])
	deviceID, generation, sessionSalt := nextEngineIdentity(cfg, &persisted)
	persistState()
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
	workers, _ := strconv.Atoi(strings.TrimSpace(cfg["SETTING_workers"]))
	if workers <= 0 {
		workers = 18
	}
	hashMode := normalizeHashMode(cfg["SETTING_hashMode"], len(hashes) > 0)
	vkToken := ""
	allowRedistrib := false
	if len(hashes) > 0 && (hashMode == "auto_api" || hashMode == "auto_js") {
		emitLog(s.vkUsingLinkHashes)
		hashMode = "manual"
	}
	if hashMode == "auto_api" || hashMode == "auto_js" {
		tok, terr := ensureVkToken(cfg["MODULE_STATE"], profileDir, s)
		if terr != nil {
			if len(hashes) > 0 {
				emitLog(s.vkLoginFallbackFmt, terr)
				hashMode = "manual"
			} else {
				emitLog(s.vkLoginFailedFmt, terr)
				emitStatus(statusFatal, "vk login failed")
				log.Fatalf("vk token: %v", terr)
			}
		} else {
			vkToken = tok
		}
	}
	switch hashMode {
	case "auto_api":
		emitProgress("%s", s.vkAutoAPIProgress)
		started, aerr := startVkAutoCalls(vkToken, workers)
		if errors.Is(aerr, errVkTokenInvalid) {
			saveVkToken("")
			emitProgress("%s", s.vkLoginProgress)
			fresh, ferr := requestVkAccessToken(profileDir)
			if ferr != nil {
				if len(hashes) > 0 {
					emitLog(s.vkLoginFallbackFmt, ferr)
					hashMode = "manual"
					break
				}
				emitLog(s.vkLoginFailedFmt, ferr)
				emitStatus(statusFatal, "vk login failed")
				log.Fatalf("vk token: %v", ferr)
			}
			vkToken = fresh
			saveVkToken(vkToken)
			started, aerr = startVkAutoCalls(vkToken, workers)
		}
		if hashMode != "auto_api" {
			break
		}
		if aerr != nil || len(started.Hashes) == 0 {
			if aerr == nil {
				aerr = fmt.Errorf("empty hash list")
			}
			if len(hashes) > 0 {
				emitLog(s.vkLoginFallbackFmt, aerr)
				hashMode = "manual"
				break
			}
			emitLog(s.vkAutoAPIFailedFmt, aerr)
			emitStatus(statusFatal, "vk auto api failed")
			log.Fatalf("vk auto api: %v", aerr)
		}
		hashes = started.Hashes
		allowRedistrib = started.needsRedistribution()
		defer finishVkAutoCalls(vkToken, started.Calls)
	case "auto_js":
		// токен уже в vkToken — rust создаёт звонок сам
	default:
		if len(hashes) == 0 {
			emitLog(s.missingHashes)
			emitStatus(statusFatal, "missing vk hashes")
			log.Fatalf("missing vk hashes")
		}
	}

	dialTimeout := settingDuration(cfg, "SETTING_dialTimeoutSec", defaultDialSec)
	obfs := strings.TrimSpace(cfg["SETTING_obfs"])
	turnTransport := strings.TrimSpace(cfg["SETTING_turnTransport"])

	resolver := newProtectedResolver(cfg["DNS_SERVERS"], protectPath)
	proxyURL, stopProxy, perr := startProtectHTTPProxy(protectPath, resolver)
	if perr != nil {
		emitLog("CSQTT: off-TUN HTTP proxy: %v", perr)
		stopProxy = func() {}
	} else {
		defer stopProxy()
	}

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

	engineJSON := map[string]any{
		"peer":           link.peerAddr(),
		"password":       link.Password,
		"hashes":         strings.Join(hashes, ","),
		"workers":        workers,
		"device_id":      deviceID,
		"generation":     generation,
		"salt":           sessionSalt,
		"captcha_mode":   "auto",
		"obfs":           obfs,
		"turn_transport": turnTransport,
		"fingerprint":    "firefox",
	}
	if proxyURL != "" {
		engineJSON["http_proxy"] = proxyURL
	}
	if hashMode == "auto_js" && vkToken != "" {
		engineJSON["vk_hash_mode"] = "auto_js"
		engineJSON["vk_js_token"] = vkToken
	}
	if allowRedistrib {
		engineJSON["allow_hash_redistribution"] = true
	}
	engineCfg, _ := json.Marshal(engineJSON)

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

type savedState struct {
	VKToken    string `json:"vk_token"`
	DeviceID   string `json:"device_id"`
	Generation uint64 `json:"generation"`
}

var persisted savedState

func restoreSavedState(blob string) savedState {
	var st savedState
	blob = strings.TrimSpace(blob)
	if blob == "" {
		return st
	}
	raw := []byte(blob)
	if dec, err := base64.StdEncoding.DecodeString(blob); err == nil && len(dec) > 0 {
		raw = dec
	}
	_ = json.Unmarshal(raw, &st)
	st.VKToken = strings.TrimSpace(st.VKToken)
	st.DeviceID = strings.TrimSpace(st.DeviceID)
	return st
}

func restoredVkToken(blob string) string {
	return restoreSavedState(blob).VKToken
}

func persistState() {
	body, err := json.Marshal(persisted)
	if err != nil {
		return
	}
	fmt.Printf("STATE_SAVE|%s\n", base64.StdEncoding.EncodeToString(body))
	_ = os.Stdout.Sync()
}

func nextEngineIdentity(cfg map[string]string, st *savedState) (deviceID string, generation uint64, salt string) {
	deviceID = strings.TrimSpace(cfg["DEVICE_ID"])
	if deviceID == "" {
		deviceID = strings.TrimSpace(st.DeviceID)
	}
	if deviceID == "" {
		deviceID = randomHex(16)
	}
	if len(deviceID) > 128 {
		deviceID = deviceID[:128]
	}
	st.DeviceID = deviceID
	if st.Generation < ^uint64(0) {
		st.Generation++
	}
	if st.Generation == 0 {
		st.Generation = 1
	}
	return deviceID, st.Generation, randomHex(16)
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func normalizeHashMode(raw string, hasHashes bool) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "auto", "auto_api":
		return "auto_api"
	case "auto_js":
		return "auto_js"
	case "manual":
		return "manual"
	case "":
		if hasHashes {
			return "manual"
		}
		return "auto_api"
	default:
		return "manual"
	}
}

func ensureVkToken(stateBlob, profileDir string, s csqttStrings) (string, error) {
	if tok := strings.TrimSpace(persisted.VKToken); tok != "" {
		return tok, nil
	}
	if tok := restoredVkToken(stateBlob); tok != "" {
		persisted.VKToken = tok
		return tok, nil
	}
	emitProgress("%s", s.vkLoginProgress)
	tok, err := requestVkAccessToken(profileDir)
	if err != nil {
		return "", err
	}
	saveVkToken(tok)
	return tok, nil
}

func saveVkToken(token string) {
	persisted.VKToken = strings.TrimSpace(token)
	persistState()
}

func requestVkAccessToken(profileDir string) (string, error) {
	if profileDir == "" {
		return "", fmt.Errorf("profileDir not set")
	}
	id := fmt.Sprintf("vk-oauth-%d", time.Now().UnixNano())
	res, cancelled := runAction(profileDir, id, map[string]any{
		"type":          "webview",
		"mode":          "navigation",
		"url":           []string{vkOAuthURL, vkOAuthURLCom},
		"urlPattern":    "blank.html",
		"param":         "access_token",
		"urlTimeoutSec": int(vkOAuthTimeout / time.Second),
		"injectJs":      vkOAuthHoistJS,
	})
	if cancelled {
		return "", fmt.Errorf("VK login cancelled")
	}
	tok, err := parseVkAccessToken(res)
	if err != nil {
		return "", err
	}
	return tok, nil
}

func parseVkAccessToken(res string) (string, error) {
	res = strings.TrimSpace(res)
	if res == "" || strings.EqualFold(res, "CANCELLED") {
		return "", fmt.Errorf("VK login cancelled")
	}
	if strings.HasPrefix(strings.ToLower(res), "error:") {
		return "", fmt.Errorf("VK login failed: %s", res)
	}
	if tok := extractAccessToken(res); tok != "" {
		return tok, nil
	}
	var payload map[string]any
	if json.Unmarshal([]byte(res), &payload) == nil {
		if tok := extractAccessToken(fmt.Sprint(payload["access_token"])); tok != "" {
			return tok, nil
		}
		if t, ok := payload["access_token"].(string); ok {
			if tok := strings.TrimSpace(t); looksLikeVkToken(tok) {
				return tok, nil
			}
		}
	}
	if looksLikeVkToken(res) {
		return res, nil
	}
	if dec, err := base64.StdEncoding.DecodeString(res); err == nil {
		s := strings.TrimSpace(string(dec))
		if tok := extractAccessToken(s); tok != "" {
			return tok, nil
		}
		if looksLikeVkToken(s) {
			return s, nil
		}
	}
	return "", fmt.Errorf("empty access_token")
}

func extractAccessToken(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || s == "<nil>" {
		return ""
	}
	if i := strings.Index(s, "access_token="); i >= 0 {
		rest := s[i+len("access_token="):]
		if j := strings.IndexAny(rest, "&?#"); j >= 0 {
			rest = rest[:j]
		}
		if u, err := url.QueryUnescape(rest); err == nil && strings.TrimSpace(u) != "" {
			rest = u
		}
		rest = strings.TrimSpace(rest)
		if looksLikeVkToken(rest) {
			return rest
		}
	}
	return ""
}

func looksLikeVkToken(s string) bool {
	if len(s) < 20 || strings.ContainsAny(s, " \t\r\n<>\"'") {
		return false
	}
	low := strings.ToLower(s)
	if strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") {
		return false
	}
	return true
}

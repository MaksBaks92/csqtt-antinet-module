// SPDX-License-Identifier: MIT
package main

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Zombie data path: helper process + TURN control plane stay up, but DialTCP through
// gVisor→engine hangs until dialTimeout (exactly 20s) and SOCKS still accepts with scraps.
// Host FIRE needs 3 SOCKS rejects / 60s and gets reset by those scraps — so the module must
// self-heal (qWDTT relayWatchdog pattern: detect → recycle transport → give up → exit).

const (
	dataPathDialFailThreshold = 3
	dataPathRecycleMinGap     = 45 * time.Second
	dataPathMaxRecycles       = 4
	dataPathEngineSettle      = 800 * time.Millisecond
)

type dataPathGuard struct {
	mu sync.Mutex

	cfgJSON     string
	readyWaitMs int
	tunIP       string

	addr atomic.Pointer[net.UDPAddr]

	dialFails   int
	recycles    int
	lastRecycle time.Time
	recycling   bool
	paused      bool // netlost: do not burn dial budget
	exiting     bool

	stopFn  func()
	startFn func(string) error
	waitFn  func(int) error
	portFn  func() int
	ipFn    func() string
	exitFn  func(code int)
	nowFn   func() time.Time
	logFn   func(format string, args ...any)
	statusFn func(kind, detail string)
}

func newDataPathGuard(cfgJSON string, readyWait time.Duration, pktPort int, tunIP string) *dataPathGuard {
	g := &dataPathGuard{
		cfgJSON:     cfgJSON,
		readyWaitMs: int(readyWait / time.Millisecond),
		tunIP:       strings.TrimSpace(tunIP),
		stopFn:      engineStop,
		startFn:     engineStart,
		waitFn:      engineWaitReady,
		portFn:      enginePacketPort,
		ipFn:        engineTunIP,
		exitFn:      os.Exit,
		nowFn:       time.Now,
		logFn:       emitLog,
		statusFn:    emitStatus,
	}
	g.setPacketPort(pktPort)
	return g
}

func (g *dataPathGuard) setPacketPort(port int) {
	if port <= 0 || port > 65535 {
		g.addr.Store(nil)
		return
	}
	g.addr.Store(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
}

func (g *dataPathGuard) packetAddr() *net.UDPAddr {
	return g.addr.Load()
}

func (g *dataPathGuard) rejecting() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.recycling || g.paused || g.exiting
}

func (g *dataPathGuard) setPaused(v bool) {
	g.mu.Lock()
	g.paused = v
	g.mu.Unlock()
}

func isDialTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "deadline exceeded") || strings.Contains(s, "i/o timeout")
}

// noteDialResult — успех сбрасывает счётчик; ровно dial-timeout копит к порогу recycle.
func (g *dataPathGuard) noteDialResult(err error) {
	if g == nil {
		return
	}
	if err == nil {
		g.mu.Lock()
		g.dialFails = 0
		g.recycles = 0 // traffic returned — allow future recoveries from a clean slate
		g.mu.Unlock()
		return
	}
	if !isDialTimeout(err) {
		return
	}
	g.mu.Lock()
	g.dialFails++
	n := g.dialFails
	g.mu.Unlock()
	if n >= dataPathDialFailThreshold {
		go g.requestRecycle("dial-timeouts")
	}
}

func (g *dataPathGuard) onHostEvent(event string) {
	if g == nil {
		return
	}
	switch event {
	case "netlost":
		g.setPaused(true)
		g.logFn("CSQTT: сеть пропала — SOCKS временно отклоняет дозвоны")
	case "netback":
		g.setPaused(false)
		g.logFn("CSQTT: сеть вернулась — перезапускаю data path")
		go g.requestRecycle("netback")
	case "stall":
		g.logFn("CSQTT: stall от хоста — перезапускаю data path")
		go g.requestRecycle("stall")
	case "handover":
		g.logFn("CSQTT: handover — перезапускаю data path (не ждём самовосстановления воркеров)")
		go g.requestRecycle("handover")
	}
}

func (g *dataPathGuard) requestRecycle(reason string) {
	if g == nil {
		return
	}
	g.mu.Lock()
	if g.exiting || g.recycling {
		g.mu.Unlock()
		return
	}
	now := g.nowFn()
	if !g.lastRecycle.IsZero() && now.Sub(g.lastRecycle) < dataPathRecycleMinGap {
		g.mu.Unlock()
		return
	}
	if g.recycles >= dataPathMaxRecycles {
		g.exiting = true
		g.mu.Unlock()
		g.logFn("CSQTT: data path не ожил после %d перезапусков (%s) — выхожу", dataPathMaxRecycles, reason)
		g.statusFn(statusFatal, "data path recycle exhausted")
		g.exitFn(42)
		return
	}
	g.recycling = true
	g.lastRecycle = now
	g.recycles++
	streak := g.recycles
	cfg := g.cfgJSON
	readyMs := g.readyWaitMs
	wantIP := g.tunIP
	g.mu.Unlock()

	g.logFn("CSQTT: data path мёртв (%s) — перезапуск движка #%d", reason, streak)

	g.stopFn()
	time.Sleep(dataPathEngineSettle)

	if err := g.startFn(cfg); err != nil {
		g.failRecycle(reason, err)
		return
	}
	if err := g.waitFn(readyMs); err != nil {
		g.failRecycle(reason, err)
		return
	}
	newIP := strings.TrimSpace(g.ipFn())
	if wantIP != "" && newIP != "" && newIP != wantIP {
		g.logFn("CSQTT: после recycle TUN IP сменился (%s→%s) — полный рестарт процесса", wantIP, newIP)
		g.mu.Lock()
		g.exiting = true
		g.recycling = false
		g.mu.Unlock()
		g.statusFn(statusFatal, "tun ip changed on recycle")
		g.exitFn(42)
		return
	}
	port := g.portFn()
	if port <= 0 || port > 65535 {
		g.failRecycle(reason, errors.New("bad packet port"))
		return
	}
	g.setPacketPort(port)

	g.mu.Lock()
	g.recycling = false
	g.dialFails = 0
	g.mu.Unlock()
	g.logFn("CSQTT: движок перезапущен · pkt=%d", port)
}

func (g *dataPathGuard) failRecycle(reason string, err error) {
	g.logFn("CSQTT: recycle движка не удался (%s): %v — выхожу", reason, err)
	g.mu.Lock()
	g.exiting = true
	g.recycling = false
	g.mu.Unlock()
	g.statusFn(statusFatal, "engine recycle failed")
	g.exitFn(42)
}

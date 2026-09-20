// SPDX-License-Identifier: MIT
package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestIsDialTimeout(t *testing.T) {
	if !isDialTimeout(context.DeadlineExceeded) {
		t.Fatal("DeadlineExceeded")
	}
	if !isDialTimeout(errors.New("tunnel dial: context deadline exceeded")) {
		t.Fatal("string deadline")
	}
	if isDialTimeout(errors.New("connection refused")) {
		t.Fatal("refused must not count")
	}
	if isDialTimeout(nil) {
		t.Fatal("nil")
	}
}

func TestDataPathGuardRecyclesAfterDialTimeouts(t *testing.T) {
	var stops, starts, waits atomic.Int32
	var exited atomic.Int32
	port := 41000
	g := &dataPathGuard{
		cfgJSON:     `{"peer":"x"}`,
		readyWaitMs: 1000,
		tunIP:       "10.0.0.2",
		stopFn:      func() { stops.Add(1) },
		startFn: func(string) error {
			starts.Add(1)
			return nil
		},
		waitFn: func(int) error {
			waits.Add(1)
			return nil
		},
		portFn: func() int {
			port++
			return port
		},
		ipFn:     func() string { return "10.0.0.2" },
		exitFn:   func(int) { exited.Add(1) },
		nowFn:    time.Now,
		logFn:    func(string, ...any) {},
		statusFn: func(string, string) {},
	}
	g.setPacketPort(41000)

	for i := 0; i < dataPathDialFailThreshold-1; i++ {
		g.noteDialResult(context.DeadlineExceeded)
	}
	time.Sleep(20 * time.Millisecond)
	if starts.Load() != 0 {
		t.Fatalf("premature recycle: starts=%d", starts.Load())
	}

	g.noteDialResult(context.DeadlineExceeded)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && starts.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if starts.Load() != 1 || stops.Load() != 1 || waits.Load() != 1 {
		t.Fatalf("recycle: stop=%d start=%d wait=%d", stops.Load(), starts.Load(), waits.Load())
	}
	if exited.Load() != 0 {
		t.Fatal("should not exit on successful recycle")
	}
	addr := g.packetAddr()
	if addr == nil || addr.Port != 41001 {
		t.Fatalf("packet addr not updated: %+v", addr)
	}
	if g.rejecting() {
		t.Fatal("should accept after recycle")
	}
}

func TestDataPathGuardResetsOnDialOK(t *testing.T) {
	var starts atomic.Int32
	g := &dataPathGuard{
		cfgJSON:     `{}`,
		readyWaitMs: 100,
		stopFn:      func() {},
		startFn:     func(string) error { starts.Add(1); return nil },
		waitFn:      func(int) error { return nil },
		portFn:      func() int { return 1 },
		ipFn:        func() string { return "" },
		exitFn:      func(int) {},
		nowFn:       time.Now,
		logFn:       func(string, ...any) {},
		statusFn:    func(string, string) {},
	}
	g.noteDialResult(context.DeadlineExceeded)
	g.noteDialResult(context.DeadlineExceeded)
	g.noteDialResult(nil)
	g.noteDialResult(context.DeadlineExceeded)
	g.noteDialResult(context.DeadlineExceeded)
	time.Sleep(30 * time.Millisecond)
	if starts.Load() != 0 {
		t.Fatalf("dial OK should reset streak, starts=%d", starts.Load())
	}
}

func TestDataPathGuardExitsAfterMaxRecycles(t *testing.T) {
	var exited atomic.Int32
	now := time.Now()
	g := &dataPathGuard{
		cfgJSON:     `{}`,
		readyWaitMs: 100,
		tunIP:       "10.0.0.2",
		stopFn:      func() {},
		startFn:     func(string) error { return nil },
		waitFn:      func(int) error { return nil },
		portFn:      func() int { return 42000 },
		ipFn:        func() string { return "10.0.0.2" },
		exitFn:      func(int) { exited.Add(1) },
		nowFn:       func() time.Time { return now },
		logFn:       func(string, ...any) {},
		statusFn:    func(string, string) {},
	}
	for i := 0; i < dataPathMaxRecycles; i++ {
		g.requestRecycle("test")
		now = now.Add(dataPathRecycleMinGap + time.Second)
	}
	g.requestRecycle("test-exhausted")
	if exited.Load() != 1 {
		t.Fatalf("expected exit after max recycles, got %d", exited.Load())
	}
}

func TestDataPathGuardRejectingWhilePaused(t *testing.T) {
	g := &dataPathGuard{
		nowFn:    time.Now,
		logFn:    func(string, ...any) {},
		statusFn: func(string, string) {},
		exitFn:   func(int) {},
	}
	g.setPaused(true)
	if !g.rejecting() {
		t.Fatal("paused must reject")
	}
	g.setPaused(false)
	if g.rejecting() {
		t.Fatal("unpaused")
	}
}

func TestDataPathGuardCooldown(t *testing.T) {
	var starts atomic.Int32
	now := time.Now()
	g := &dataPathGuard{
		cfgJSON:     `{}`,
		readyWaitMs: 100,
		tunIP:       "10.0.0.2",
		stopFn:      func() {},
		startFn:     func(string) error { starts.Add(1); return nil },
		waitFn:      func(int) error { return nil },
		portFn:      func() int { return 43000 },
		ipFn:        func() string { return "10.0.0.2" },
		exitFn:      func(int) {},
		nowFn:       func() time.Time { return now },
		logFn:       func(string, ...any) {},
		statusFn:    func(string, string) {},
	}
	g.requestRecycle("a")
	g.requestRecycle("b") // within cooldown
	if starts.Load() != 1 {
		t.Fatalf("cooldown broken: starts=%d", starts.Load())
	}
}

func TestDataPathGuardRecycleAllowsZeroPacketPort(t *testing.T) {
	var exited atomic.Int32
	g := &dataPathGuard{
		cfgJSON:     `{}`,
		readyWaitMs: 100,
		tunIP:       "10.0.0.2",
		stopFn:      func() {},
		startFn:     func(string) error { return nil },
		waitFn:      func(int) error { return nil },
		portFn:      func() int { return 0 }, // in-process bridge
		ipFn:        func() string { return "10.0.0.2" },
		exitFn:      func(int) { exited.Add(1) },
		nowFn:       time.Now,
		logFn:       func(string, ...any) {},
		statusFn:    func(string, string) {},
	}
	g.requestRecycle("bridge")
	if exited.Load() != 0 {
		t.Fatal("port 0 must be valid for packet_bridge")
	}
	if g.rejecting() {
		t.Fatal("should accept after bridge recycle")
	}
}

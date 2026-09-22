// SPDX-License-Identifier: MIT
package main

import (
	"sync/atomic"
	"testing"
	"time"
)

func newRebindTestGuard(active *atomic.Int32, rebinds, starts *atomic.Int32, rebindOK bool) *dataPathGuard {
	return &dataPathGuard{
		cfgJSON:     `{}`,
		readyWaitMs: 100,
		stopFn:      func() {},
		startFn:     func(string) error { starts.Add(1); return nil },
		waitFn:      func(int) error { return nil },
		portFn:      func() int { return 0 },
		ipFn:        func() string { return "" },
		pauseFn:     func(bool) {},
		activeFn:    func() int { return int(active.Load()) },
		rebindFn: func() bool {
			rebinds.Add(1)
			return rebindOK
		},
		exitFn:   func(int) {},
		nowFn:    time.Now,
		sleepFn:  func(time.Duration) { time.Sleep(time.Millisecond) },
		logFn:    func(string, ...any) {},
		statusFn: func(string, string) {},
	}
}

func TestDataPathGuardHandoverSoftRebind(t *testing.T) {
	var active, rebinds, starts atomic.Int32
	active.Store(0)
	g := newRebindTestGuard(&active, &rebinds, &starts, true)
	g.onHostEvent("handover")
	if rebinds.Load() != 1 {
		t.Fatalf("handover must rebind: %d", rebinds.Load())
	}
	// Paths come back → watchdog exits without recycle.
	active.Store(2)
	time.Sleep(30 * time.Millisecond)
	if starts.Load() != 0 {
		t.Fatalf("no recycle when paths return: starts=%d", starts.Load())
	}
	if g.rejecting() {
		t.Fatal("soft rebind must not reject SOCKS")
	}
	if g.graceUntil.Before(time.Now()) {
		t.Fatal("rebind must arm the dial-timeout grace period")
	}
	// A second signal for the same change (own detector right after the host event) is deduped.
	g.onHostEvent("handover")
	if rebinds.Load() != 1 {
		t.Fatalf("handover within the dedupe window must be ignored: %d", rebinds.Load())
	}
}

func TestDataPathGuardHandoverFallsBackToRecycle(t *testing.T) {
	var active, rebinds, starts atomic.Int32
	g := newRebindTestGuard(&active, &rebinds, &starts, true)
	// Fake clock: the watchdog deadline elapses after a few polls.
	base := time.Now()
	var ticks atomic.Int32
	g.nowFn = func() time.Time { return base.Add(time.Duration(ticks.Load()) * 4 * time.Second) }
	g.sleepFn = func(time.Duration) { ticks.Add(1) }
	g.onHostEvent("handover")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && starts.Load() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if rebinds.Load() != 1 || starts.Load() != 1 {
		t.Fatalf("no path after rebind must recycle: rebinds=%d starts=%d", rebinds.Load(), starts.Load())
	}
}

func TestDataPathGuardHandoverWithoutRebindRecycles(t *testing.T) {
	var active, rebinds, starts atomic.Int32
	g := newRebindTestGuard(&active, &rebinds, &starts, false) // old engine: no symbol
	g.onHostEvent("handover")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && starts.Load() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if starts.Load() != 1 {
		t.Fatalf("engine without rebind must recycle: starts=%d", starts.Load())
	}
}

func TestDataPathGuardHandoverWhilePausedResumesFirst(t *testing.T) {
	var active, rebinds, starts, resumes atomic.Int32
	g := newRebindTestGuard(&active, &rebinds, &starts, true)
	g.pauseFn = func(v bool) {
		if !v {
			resumes.Add(1)
		}
	}
	g.onHostEvent("netlost")
	g.onHostEvent("handover")
	if resumes.Load() != 1 || rebinds.Load() != 1 {
		t.Fatalf("handover while paused: resumes=%d rebinds=%d", resumes.Load(), rebinds.Load())
	}
	if g.rejecting() {
		t.Fatal("must accept after handover lifted the pause")
	}
}

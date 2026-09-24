// SPDX-License-Identifier: MIT
package main

import (
	"context"
	"errors"
	"sync"
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

func TestDataPathGuardRecycleDoesNotReject(t *testing.T) {
	g := &dataPathGuard{
		recycling: true,
		nowFn:     time.Now,
		logFn:     func(string, ...any) {},
		statusFn:  func(string, string) {},
	}
	if g.rejecting() {
		t.Fatal("recycle must hold CONNECT, not reject")
	}

	var polls atomic.Int32
	paused := &dataPathGuard{
		paused:   true,
		activeFn: func() int { polls.Add(1); return 0 },
		sleepFn:  func(time.Duration) {},
		nowFn:    time.Now,
	}
	paused.waitForPath(context.Background())
	if polls.Load() != 0 {
		t.Fatalf("paused must not poll for a path: %d", polls.Load())
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

func TestDataPathGuardNetlostDefersRecycle(t *testing.T) {
	var starts, pauses atomic.Int32
	var exited atomic.Int32
	g := &dataPathGuard{
		cfgJSON:     `{}`,
		readyWaitMs: 100,
		tunIP:       "10.0.0.2",
		stopFn:      func() {},
		startFn: func(string) error {
			starts.Add(1)
			return nil
		},
		waitFn:   func(int) error { return nil },
		portFn:   func() int { return 0 },
		ipFn:     func() string { return "10.0.0.2" },
		pauseFn:  func(v bool) { if v { pauses.Add(1) } else { pauses.Add(10) } },
		exitFn:   func(int) { exited.Add(1) },
		nowFn:    time.Now,
		logFn:    func(string, ...any) {},
		statusFn: func(string, string) {},
	}
	g.onHostEvent("netlost")
	if pauses.Load() != 1 {
		t.Fatalf("engine pause on netlost: %d", pauses.Load())
	}
	for i := 0; i < dataPathDialFailThreshold; i++ {
		g.noteDialResult(context.DeadlineExceeded)
	}
	time.Sleep(30 * time.Millisecond)
	if starts.Load() != 0 {
		t.Fatalf("must not recycle while offline: starts=%d", starts.Load())
	}
	g.requestRecycle("dial-timeouts")
	if starts.Load() != 0 || exited.Load() != 0 {
		t.Fatalf("deferred recycle leaked: starts=%d exited=%d", starts.Load(), exited.Load())
	}

	g.onHostEvent("netback")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && starts.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if starts.Load() != 1 {
		t.Fatalf("netback should apply pending recycle: starts=%d", starts.Load())
	}
	if pauses.Load() < 11 {
		t.Fatalf("expected resume: pauses=%d", pauses.Load())
	}
	if exited.Load() != 0 {
		t.Fatal("must not exit")
	}
}

func TestDataPathGuardNetbackSoftResume(t *testing.T) {
	var starts, resumes atomic.Int32
	g := &dataPathGuard{
		cfgJSON:     `{}`,
		readyWaitMs: 100,
		stopFn:      func() {},
		startFn:     func(string) error { starts.Add(1); return nil },
		waitFn:      func(int) error { return nil },
		portFn:      func() int { return 0 },
		ipFn:        func() string { return "" },
		pauseFn: func(v bool) {
			if !v {
				resumes.Add(1)
			}
		},
		activeFn: func() int { return 2 }, // paths come back → watch must not recycle
		sleepFn:  func(time.Duration) {},  // soft-resume watch returns immediately
		exitFn:   func(int) {},
		nowFn:    time.Now,
		logFn:    func(string, ...any) {},
		statusFn: func(string, string) {},
	}
	g.onHostEvent("netlost")
	g.onHostEvent("netback")
	time.Sleep(30 * time.Millisecond)
	if starts.Load() != 0 {
		t.Fatalf("soft resume must not recycle: starts=%d", starts.Load())
	}
	if resumes.Load() != 1 {
		t.Fatalf("expected engine resume: %d", resumes.Load())
	}
	if g.rejecting() {
		t.Fatal("must accept after netback")
	}
}

func TestDataPathGuardSoftResumeDeadRecycles(t *testing.T) {
	var starts, nudges atomic.Int32
	g := &dataPathGuard{
		cfgJSON:     `{}`,
		readyWaitMs: 100,
		stopFn:      func() {},
		startFn:     func(string) error { starts.Add(1); return nil },
		waitFn:      func(int) error { return nil },
		portFn:      func() int { return 0 },
		ipFn:        func() string { return "" },
		pauseFn:     func(bool) {},
		activeFn:    func() int { return 0 },
		nudgeFn:     func() { nudges.Add(1) },
		sleepFn:     func(time.Duration) {},
		exitFn:      func(int) {},
		nowFn:       time.Now,
		logFn:       func(string, ...any) {},
		statusFn:    func(string, string) {},
	}
	g.onHostEvent("netlost")
	g.onHostEvent("netback")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && starts.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if nudges.Load() < 1 {
		t.Fatalf("expected nudge on soft resume: %d", nudges.Load())
	}
	if starts.Load() != 1 {
		t.Fatalf("READY=0 after soft resume should cold-recycle: starts=%d", starts.Load())
	}
}

func TestDataPathGuardFailRecycleOfflineDefers(t *testing.T) {
	var exited atomic.Int32
	g := &dataPathGuard{
		paused:   true,
		exitFn:   func(int) { exited.Add(1) },
		logFn:    func(string, ...any) {},
		statusFn: func(string, string) {},
		nowFn:    time.Now,
	}
	g.recycling = true
	g.failRecycle("test", errors.New("dns down"))
	if exited.Load() != 0 {
		t.Fatal("must not fatal while paused")
	}
	if !g.pendingRecycle {
		t.Fatal("should pending")
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

func TestSuspendGapFrom(t *testing.T) {
	if got := suspendGapFrom(3*time.Second, 603*time.Second); got != 600*time.Second {
		t.Fatalf("gap=%v", got)
	}
	if got := suspendGapFrom(3*time.Second, 3*time.Second+50*time.Millisecond); got != 50*time.Millisecond {
		t.Fatalf("jitter gap=%v", got)
	}
	if got := suspendGapFrom(3*time.Second, 2*time.Second); got != 0 {
		t.Fatalf("negative must clamp: %v", got)
	}
	prev := time.Now()
	if got := suspendGap(prev, prev.Add(5*time.Second)); got != 0 {
		t.Fatalf("Add keeps both readings in step: %v", got)
	}
}

func TestDataPathGuardWakeGraceIgnoresStaleTimeouts(t *testing.T) {
	var starts, nudges atomic.Int32
	now := time.Now()
	g := &dataPathGuard{
		cfgJSON:     `{}`,
		readyWaitMs: 100,
		stopFn:      func() {},
		startFn:     func(string) error { starts.Add(1); return nil },
		waitFn:      func(int) error { return nil },
		portFn:      func() int { return 0 },
		ipFn:        func() string { return "" },
		nudgeFn:     func() { nudges.Add(1) },
		activeFn:    func() int { return 2 },
		sleepFn:     func(time.Duration) {},
		exitFn:      func(int) {},
		nowFn:       func() time.Time { return now },
		logFn:       func(string, ...any) {},
		statusFn:    func(string, string) {},
	}
	g.onWake(10 * time.Minute)
	if nudges.Load() != 1 {
		t.Fatalf("wake must nudge the engine: %d", nudges.Load())
	}
	// Dials that were in flight during the sleep time out now — not evidence of a zombie.
	for i := 0; i < dataPathDialFailThreshold+2; i++ {
		g.noteDialResult(context.DeadlineExceeded)
	}
	time.Sleep(30 * time.Millisecond)
	if starts.Load() != 0 {
		t.Fatalf("grace window must swallow stale timeouts: starts=%d", starts.Load())
	}
	// After the grace window the detector is armed again.
	now = now.Add(dataPathWakeGrace + time.Second)
	for i := 0; i < dataPathDialFailThreshold; i++ {
		g.noteDialResult(context.DeadlineExceeded)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && starts.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if starts.Load() != 1 {
		t.Fatalf("post-grace timeouts must recycle: starts=%d", starts.Load())
	}
}

func TestDataPathGuardWakeWhilePausedProbesNetwork(t *testing.T) {
	var starts, resumes, nudges, probes atomic.Int32
	g := &dataPathGuard{
		cfgJSON:     `{}`,
		readyWaitMs: 100,
		stopFn:      func() {},
		startFn:     func(string) error { starts.Add(1); return nil },
		waitFn:      func(int) error { return nil },
		portFn:      func() int { return 0 },
		ipFn:        func() string { return "" },
		pauseFn: func(v bool) {
			if !v {
				resumes.Add(1)
			}
		},
		nudgeFn:  func() { nudges.Add(1) },
		probeFn:  func() bool { probes.Add(1); return probes.Load() >= 2 },
		activeFn: func() int { return 2 },
		sleepFn:  func(time.Duration) {}, // watchdog must not be the one resuming here
		exitFn:   func(int) {},
		nowFn:    time.Now,
		logFn:    func(string, ...any) {},
		statusFn: func(string, string) {},
	}
	g.paused = true // netlost already applied, no watchdog goroutine in this test
	g.pauseGen = 7

	g.onWake(5 * time.Minute) // probe #1 → false: still offline
	if !g.rejecting() || resumes.Load() != 0 {
		t.Fatal("failed probe must keep the pause")
	}
	g.onWake(3 * time.Minute) // probe #2 → true: network is back without a netback
	if g.rejecting() || resumes.Load() != 1 {
		t.Fatalf("successful probe must resume: rejecting=%v resumes=%d", g.rejecting(), resumes.Load())
	}
	if nudges.Load() != 1 {
		t.Fatalf("no pending recycle → soft nudge expected: %d", nudges.Load())
	}
	time.Sleep(30 * time.Millisecond)
	if starts.Load() != 0 {
		t.Fatalf("soft resume must not recycle: starts=%d", starts.Load())
	}
}

func TestDataPathGuardPausedWatchdogSelfNetback(t *testing.T) {
	var resumes, probes atomic.Int32
	var slept []time.Duration
	var mu sync.Mutex
	g := &dataPathGuard{
		cfgJSON:     `{}`,
		readyWaitMs: 100,
		stopFn:      func() {},
		startFn:     func(string) error { return nil },
		waitFn:      func(int) error { return nil },
		portFn:      func() int { return 0 },
		ipFn:        func() string { return "" },
		pauseFn: func(v bool) {
			if !v {
				resumes.Add(1)
			}
		},
		probeFn: func() bool { return probes.Add(1) >= 3 },
		activeFn: func() int { return 2 },
		sleepFn: func(d time.Duration) {
			mu.Lock()
			slept = append(slept, d)
			mu.Unlock()
		},
		exitFn:   func(int) {},
		nowFn:    time.Now,
		logFn:    func(string, ...any) {},
		statusFn: func(string, string) {},
	}
	g.onHostEvent("netlost")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && resumes.Load() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if resumes.Load() != 1 || g.rejecting() {
		t.Fatalf("watchdog must resume after a successful probe: resumes=%d", resumes.Load())
	}
	mu.Lock()
	got := make([]time.Duration, 0, len(slept))
	for _, d := range slept {
		if d == dataPathSoftResumeWatch {
			continue // soft-resume liveness watch, not the paused probe schedule
		}
		got = append(got, d)
	}
	mu.Unlock()
	want := dataPathPausedProbeDelays[:3]
	if len(got) != len(want) {
		t.Fatalf("probe schedule: got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("probe schedule[%d]: got %v want %v", i, got[i], want[i])
		}
	}
	// A stale watchdog (older pause generation) must not touch a fresh pause.
	g.mu.Lock()
	g.paused = true
	g.pauseGen = 5
	g.mu.Unlock()
	g.probeSucceeded(1, "stale")
	if !g.rejecting() || resumes.Load() != 1 {
		t.Fatal("stale generation must be ignored")
	}
}

func TestDataPathGuardStallWhilePausedResumesThenRecycles(t *testing.T) {
	var starts, resumes atomic.Int32
	g := &dataPathGuard{
		cfgJSON:     `{}`,
		readyWaitMs: 100,
		stopFn:      func() {},
		startFn:     func(string) error { starts.Add(1); return nil },
		waitFn:      func(int) error { return nil },
		portFn:      func() int { return 0 },
		ipFn:        func() string { return "" },
		pauseFn: func(v bool) {
			if !v {
				resumes.Add(1)
			}
		},
		exitFn:   func(int) {},
		nowFn:    time.Now,
		logFn:    func(string, ...any) {},
		statusFn: func(string, string) {},
	}
	g.onHostEvent("netlost")
	g.onHostEvent("stall") // host has a network if it could run a health check
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && starts.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if resumes.Load() != 1 {
		t.Fatalf("stall must lift the pause: resumes=%d", resumes.Load())
	}
	if starts.Load() != 1 {
		t.Fatalf("stall must recycle once resumed: starts=%d", starts.Load())
	}
	if g.rejecting() {
		t.Fatal("should accept after stall recycle")
	}
}

func TestDataPathGuardWaitForPath(t *testing.T) {
	var polls atomic.Int32
	now := time.Now()
	g := &dataPathGuard{
		activeFn: func() int {
			if polls.Add(1) >= 4 {
				return 27
			}
			return 0
		},
		sleepFn: func(time.Duration) {},
		nowFn:   func() time.Time { return now },
		logFn:   func(string, ...any) {},
	}
	g.waitForPath(context.Background())
	if polls.Load() != 4 {
		t.Fatalf("must return as soon as a path appears: polls=%d", polls.Load())
	}

	// Unknown (-1: old engine build) and healthy (>0) skip the wait entirely.
	for _, v := range []int{-1, 1} {
		var calls atomic.Int32
		h := &dataPathGuard{activeFn: func() int { calls.Add(1); return v }, sleepFn: func(time.Duration) {}, nowFn: time.Now}
		h.waitForPath(context.Background())
		if calls.Load() != 1 {
			t.Fatalf("active=%d must not poll: calls=%d", v, calls.Load())
		}
	}

	// Cancelled ctx returns without waiting for the cap.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var calls atomic.Int32
	c := &dataPathGuard{activeFn: func() int { calls.Add(1); return 0 }, sleepFn: func(time.Duration) {}, nowFn: time.Now}
	c.waitForPath(ctx)
	if calls.Load() != 1 {
		t.Fatalf("cancelled ctx must stop polling: calls=%d", calls.Load())
	}

	// Cap: nowFn advances past the deadline → returns even with zero paths, and asks for a recycle.
	step := time.Now()
	var starts atomic.Int32
	d := &dataPathGuard{
		cfgJSON:  `{}`,
		activeFn: func() int { return 0 },
		sleepFn:  func(dur time.Duration) { step = step.Add(dur) },
		nowFn:    func() time.Time { return step },
		stopFn:   func() {},
		startFn:  func(string) error { starts.Add(1); return nil },
		waitFn:   func(int) error { return nil },
		portFn:   func() int { return 0 },
		ipFn:     func() string { return "" },
		exitFn:   func(int) {},
		logFn:    func(string, ...any) {},
		statusFn: func(string, string) {},
	}
	d.waitForPath(context.Background())
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && starts.Load() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if starts.Load() != 1 {
		t.Fatalf("zero-path wait cap must recycle: starts=%d", starts.Load())
	}
}

func TestNetworkProbeHost(t *testing.T) {
	if got := networkProbeHost("csqtt.example.org:5000"); got != "csqtt.example.org" {
		t.Fatalf("host:port → %q", got)
	}
	if got := networkProbeHost("csqtt.example.org"); got != "csqtt.example.org" {
		t.Fatalf("bare host → %q", got)
	}
	if got := networkProbeHost("10.1.2.3:5000"); got != "api.vk.com" {
		t.Fatalf("ip literal → %q", got)
	}
	if got := networkProbeHost(""); got != "api.vk.com" {
		t.Fatalf("empty → %q", got)
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

func TestDataPathGuardRebuildsTunOnIPChange(t *testing.T) {
	var exited atomic.Int32
	var rebuilt atomic.Int32
	g := &dataPathGuard{
		cfgJSON:     `{}`,
		readyWaitMs: 100,
		tunIP:       "10.0.0.2",
		stopFn:      func() {},
		startFn:     func(string) error { return nil },
		waitFn:      func(int) error { return nil },
		portFn:      func() int { return 0 },
		ipFn:        func() string { return "10.0.0.9" },
		rebuildTunFn: func(newIP string) error {
			if newIP != "10.0.0.9" {
				t.Fatalf("rebuild ip: %s", newIP)
			}
			rebuilt.Add(1)
			return nil
		},
		exitFn:   func(int) { exited.Add(1) },
		nowFn:    time.Now,
		logFn:    func(string, ...any) {},
		statusFn: func(string, string) {},
	}
	g.requestRecycle("ip-change")
	if exited.Load() != 0 {
		t.Fatal("tun ip change must rebuild, not exit")
	}
	if rebuilt.Load() != 1 {
		t.Fatalf("rebuildTunFn calls=%d", rebuilt.Load())
	}
	if g.tunIP != "10.0.0.9" {
		t.Fatalf("tunIP not updated: %s", g.tunIP)
	}
}

func TestDataPathGuardRecycleStreakSurvivesOneOK(t *testing.T) {
	now := time.Now()
	g := &dataPathGuard{
		recycles:    3,
		lastRecycle: now,
		nowFn:       func() time.Time { return now },
		logFn:       func(string, ...any) {},
		statusFn:    func(string, string) {},
	}
	g.noteDialResult(nil)
	if g.recycles != 3 {
		t.Fatalf("one OK inside stable window must keep streak: %d", g.recycles)
	}
	now = now.Add(dataPathRecycleStable)
	g.noteDialResult(nil)
	if g.recycles != 0 {
		t.Fatalf("OK after stable window must clear streak: %d", g.recycles)
	}
}

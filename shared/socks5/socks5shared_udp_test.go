// SPDX-License-Identifier: MIT

package main

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestSweepIdleUDPTargets(t *testing.T) {
	keepA, keepB := net.Pipe()
	dropA, dropB := net.Pipe()
	t.Cleanup(func() {
		_ = keepA.Close()
		_ = keepB.Close()
		_ = dropA.Close()
		_ = dropB.Close()
	})
	now := time.Now()
	live, _ := netip.ParseAddrPort("192.0.2.1:443")
	stale, _ := netip.ParseAddrPort("192.0.2.2:443")
	targets := map[netip.AddrPort]*udpNatEntry{
		live:  {conn: keepA, last: now.Add(-socksUDPIdleTTL / 2)},
		stale: {conn: dropA, last: now.Add(-socksUDPIdleTTL - time.Second)},
	}
	sweepIdleUDPTargets(targets, now)
	if _, ok := targets[live]; !ok {
		t.Fatal("fresh mapping must stay")
	}
	if _, ok := targets[stale]; ok {
		t.Fatal("idle mapping past TTL must go")
	}
	if _, err := dropB.Read(make([]byte, 1)); err == nil {
		t.Fatal("closed idle conn must fail reads")
	}
}

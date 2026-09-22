// SPDX-License-Identifier: MIT
package main

import "testing"

func TestNetChangeTracker(t *testing.T) {
	var tr netChangeTracker
	if _, _, changed := tr.observe("192.168.1.5", true); changed {
		t.Fatal("first observation is a baseline, not a change")
	}
	if _, _, changed := tr.observe("192.168.1.5", true); changed {
		t.Fatal("same address is not a change")
	}
	// No route (netlost) keeps the baseline.
	if _, _, changed := tr.observe("", false); changed {
		t.Fatal("no route is not a change")
	}
	from, to, changed := tr.observe("10.20.30.40", true)
	if !changed || from != "192.168.1.5" || to != "10.20.30.40" {
		t.Fatalf("Wi-Fi → cellular must be detected: %v %s→%s", changed, from, to)
	}
	if _, _, changed := tr.observe("10.20.30.40", true); changed {
		t.Fatal("stable after the change")
	}
}

func TestNetChangeTargetLiteralPeer(t *testing.T) {
	if got := netChangeTarget("203.0.113.7:5555", nil); got != "203.0.113.7:5555" {
		t.Fatalf("literal peer: %q", got)
	}
	if got := netChangeTarget("203.0.113.7", nil); got != "203.0.113.7:443" {
		t.Fatalf("literal peer without port: %q", got)
	}
	if got := netChangeTarget("example.invalid:5555", nil); got != "" {
		t.Fatalf("hostname without resolver must not resolve via default resolver: %q", got)
	}
}

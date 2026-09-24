// Package csqtt is the CSQTT datapath branch (server = CSQTT WIRE-3).
//
// Base: examples/modulecsqtt (helper + rust engine). This stub must be replaced
// by a thin adapter that calls the existing realMain/engine path without
// changing CSQTT wire bytes, SOCKS, or lifecycle semantics.
package csqtt

import "dual-antinet/internal/vk"

// RunConfig is host + link material for one connect.
type RunConfig struct {
	ConfigContent string
	ResolversPath string
	ProfileDir    string
	ProtectPath   string
	ListenFd      int
	Link          string
	VK            vk.Mode
}

// Run starts the CSQTT tunnel. Skeleton returns ErrNotWired.
func Run(_ RunConfig) error {
	return ErrNotWired
}

var ErrNotWired = errNotWired{}

type errNotWired struct{}

func (errNotWired) Error() string {
	return "dual/csqtt: not wired yet (phase 2: adapt examples/modulecsqtt)"
}

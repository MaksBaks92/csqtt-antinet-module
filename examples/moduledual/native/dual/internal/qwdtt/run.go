// Package qwdtt is the qWDTT datapath branch (server = user VPS, SpaceNeuroX server/).
//
// Client base: qwdtt-module native/qwdtt or upstream go_client/ (GPL-3.0).
// Do not import server/*. Control plane stays GETCONF/AUTH/GETCONF_RAW as in
// upstream protocol.go — never CSQTT WIRE GETCONF.
package qwdtt

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

// Run starts the qWDTT tunnel toward the VPS. Skeleton returns ErrNotWired.
func Run(_ RunConfig) error {
	return ErrNotWired
}

var ErrNotWired = errNotWired{}

type errNotWired struct{}

func (errNotWired) Error() string {
	return "dual/qwdtt: not wired yet (phase 3: vendor GPL client after license gate)"
}

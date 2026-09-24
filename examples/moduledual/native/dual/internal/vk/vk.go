// Package vk is the shared VK hash / TURN credential layer.
//
// Base: CSQTT module work (vkcalls, auto_js/auto_api, captcha, cache).
// Both csqtt and qwdtt branches will call into this package; they must not
// keep divergent credential fetchers long-term.
//
// Skeleton: types only — wire implementations in a later phase.
package vk

// Mode mirrors CSQTT hashMode / vkAuthMode pairing (see modulecsqtt VkModePolicy).
type Mode struct {
	Hash string // manual | auto_api | auto_js
	Auth string // vkcalls | auto_js | legacy | …
}

// Creds is the TURN material both datapaths need before talking to their own server.
type Creds struct {
	Username string
	Password string
	URLs     []string
}

// Fetch is a placeholder. Phase 4: move CSQTT VK pipeline here.
func Fetch(_ Mode, _ []string) (Creds, error) {
	return Creds{}, ErrNotWired
}

// ErrNotWired marks skeleton stubs.
var ErrNotWired = errNotWired{}

type errNotWired struct{}

func (errNotWired) Error() string { return "dual/vk: not wired yet (use CSQTT VK pipeline in phase 4)" }

// SPDX-License-Identifier: MIT
//
// Dual helper skeleton — routes AntiNet LINK to csqtt or qwdtt datapath.
// Canons shared/* are injected by build.py at build time (same as modulecsqtt).
//
// Connect is not fully wired: branches return ErrNotWired until phases 2–3.
package main

import (
	"fmt"
	"log"
	"strings"

	"dual-antinet/internal/csqtt"
	"dual-antinet/internal/qwdtt"
	"dual-antinet/internal/route"
	"dual-antinet/internal/vk"
)

// moduleCall — summarize / normalize for both schemes.
func moduleCall(verb, arg string) string {
	switch strings.ToLower(strings.TrimSpace(verb)) {
	case "summarize":
		scheme, err := route.FromLink(arg)
		if err != nil {
			return ""
		}
		return fmt.Sprintf("%s (dual skeleton)", scheme)
	case "normalize":
		// Phase 2/3: dispatch to csqtt or qwdtt normalizers.
		if _, err := route.FromLink(arg); err == nil {
			return strings.TrimSpace(arg)
		}
		return ""
	default:
		return ""
	}
}

// realMain — AntiNet entry. Parses LINK scheme and dispatches.
func realMain(configContent, resolversPath, profileDir, protectPath string, listenFd int) int {
	cfg := parseKV(configContent)
	link := strings.TrimSpace(cfg["LINK"])
	scheme, err := route.FromLink(link)
	if err != nil {
		log.Printf("dual: %v", err)
		return 1
	}

	vkMode := vk.Mode{
		Hash: strings.TrimSpace(cfg["SETTING_hashMode"]),
		Auth: strings.TrimSpace(cfg["SETTING_vkAuthMode"]),
	}
	if vkMode.Hash == "" {
		vkMode.Hash = "manual"
	}

	log.Printf("dual: scheme=%s (skeleton — datapath not wired)", scheme)

	var runErr error
	switch scheme {
	case route.SchemeCSQTT:
		runErr = csqtt.Run(csqtt.RunConfig{
			ConfigContent: configContent,
			ResolversPath: resolversPath,
			ProfileDir:    profileDir,
			ProtectPath:   protectPath,
			ListenFd:      listenFd,
			Link:          link,
			VK:            vkMode,
		})
	case route.SchemeQWDTT:
		runErr = qwdtt.Run(qwdtt.RunConfig{
			ConfigContent: configContent,
			ResolversPath: resolversPath,
			ProfileDir:    profileDir,
			ProtectPath:   protectPath,
			ListenFd:      listenFd,
			Link:          link,
			VK:            vkMode,
		})
	default:
		runErr = fmt.Errorf("internal: unknown scheme %q", scheme)
	}
	if runErr != nil {
		log.Printf("dual: %v", runErr)
		return 1
	}
	return 0
}

func parseKV(content string) map[string]string {
	out := make(map[string]string)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

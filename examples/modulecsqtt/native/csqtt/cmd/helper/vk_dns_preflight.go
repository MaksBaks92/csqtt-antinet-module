package main

import (
	"fmt"
	"strings"
)

func logVkDNSHint(resolver *protectedResolver) {
	if resolver == nil {
		return
	}
	hosts := []string{"oauth.vk.com", "api.vk.com", "api.vk.ru", "id.vk.ru", "login.vk.com", "login.vk.ru", "m.vk.com"}
	parts := make([]string, 0, len(hosts))
	for _, h := range hosts {
		ips, err := resolver.LookupHost(h)
		if err != nil || len(ips) == 0 {
			parts = append(parts, h+"=FAIL")
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%s", h, ips[0]))
	}
	emitLog("CSQTT: DNS off-TUN модуля: %s. OAuth WebView открывает только 127.0.0.1 — VK качает helper через protect", strings.Join(parts, ", "))
}

package main

import (
	"fmt"
	"strings"
)

func logVkDNSHint(resolver *protectedResolver) {
	if resolver == nil {
		return
	}
	hosts := []string{"oauth.vk.com", "api.vk.com", "m.vk.com", "login.vk.com"}
	parts := make([]string, 0, len(hosts))
	for _, h := range hosts {
		ips, err := resolver.LookupHost(h)
		if err != nil || len(ips) == 0 {
			parts = append(parts, h+"=FAIL")
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%s", h, ips[0]))
	}
	emitLog("CSQTT: DNS off-TUN модуля: %s. Окно VK в AntiNet идёт мимо protect — при ERR_NAME_NOT_RESOLVED отключите активный туннель; модуль переводит *.vk.ru → *.vk.com в WebView", strings.Join(parts, ", "))
}

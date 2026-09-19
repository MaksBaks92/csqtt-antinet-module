package main

import (
	"fmt"
	"strings"
)

func logVkDNSHint(resolver *protectedResolver) {
	if resolver == nil {
		return
	}
	// Домены апстрима (`Constants.kt`): авторизация и API живут на `vk.ru`.
	hosts := []string{"oauth.vk.ru", "api.vk.ru", "id.vk.ru", "login.vk.ru", "vk.ru"}
	parts := make([]string, 0, len(hosts))
	for _, h := range hosts {
		ips, err := resolver.LookupHost(h)
		if err != nil || len(ips) == 0 {
			parts = append(parts, h+"=FAIL")
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%s", h, ips[0]))
	}
	// Диагностика ТОЛЬКО про резолвер самого модуля (канон `shared/dns`, off-TUN): он нужен
	// helper'у для его собственных дозвонов к VK API. К webview хоста отношения не имеет — тот
	// ходит своим стеком, и правило §2.7 даёт ему обычный публичный URL.
	emitLog("CSQTT: DNS off-TUN модуля: %s", strings.Join(parts, ", "))
}

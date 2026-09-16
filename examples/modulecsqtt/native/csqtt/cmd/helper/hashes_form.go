// SPDX-License-Identifier: MIT
//
// Manual VK hashes: AntiNet settings UI cannot hide fields by enum value, so
// hash inputs are not in module.json. In Manual mode the helper opens a host
// form (up to 6 hashes) — the same idea as CSQTT's hashes dialog.

package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func promptManualHashes(profileDir string, prefill []string, s csqttStrings) ([]string, error) {
	fields := make([]map[string]any, 0, maxVkHashes)
	for i := 1; i <= maxVkHashes; i++ {
		field := map[string]any{
			"key":   fmt.Sprintf("hash%d", i),
			"label": fmt.Sprintf(s.hashFormLabelFmt, i),
			"type":  "text",
		}
		if i-1 < len(prefill) && prefill[i-1] != "" {
			field["default"] = prefill[i-1]
		}
		fields = append(fields, field)
	}
	id := fmt.Sprintf("vk-hashes-%d", time.Now().UnixNano())
	res, cancelled := runAction(profileDir, id, map[string]any{
		"type":        "form",
		"title":       s.hashFormTitle,
		"description": s.hashFormHint,
		"fields":      fields,
	})
	if cancelled {
		return nil, fmt.Errorf("%s", s.hashFormCancelled)
	}
	parsed := parseHashFormResult(res)
	if len(parsed) == 0 {
		return prefill, nil
	}
	return parsed, nil
}

func parseHashFormResult(res string) []string {
	res = strings.TrimSpace(res)
	if res == "" || strings.EqualFold(res, "CANCELLED") {
		return nil
	}
	var obj map[string]any
	if json.Unmarshal([]byte(res), &obj) == nil {
		raw := make([]string, 0, maxVkHashes)
		for i := 1; i <= maxVkHashes; i++ {
			raw = append(raw, fmt.Sprint(obj[fmt.Sprintf("hash%d", i)]))
		}
		return uniqHashes(raw)
	}
	return uniqHashes([]string{res})
}

func uniqHashes(raw []string) []string {
	seen := make(map[string]struct{}, maxVkHashes)
	out := make([]string, 0, maxVkHashes)
	for _, chunk := range raw {
		if chunk == "<nil>" {
			continue
		}
		for _, h := range splitHashes(chunk) {
			if _, ok := seen[h]; ok {
				continue
			}
			seen[h] = struct{}{}
			out = append(out, h)
			if len(out) >= maxVkHashes {
				return out
			}
		}
	}
	return out
}

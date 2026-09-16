// SPDX-License-Identifier: MIT
//
// Manual VK hashes follow the qWDTT interactive pattern: AntiNet settings
// cannot hide fields by enum, so hashes are not in module.json. In Manual
// mode the helper emits ACTION_REQUIRED webview (mode=navigation) — the same
// host UI that shows qWDTT captcha / VK-account join. type=form is a demo
// echo-module type and does not pop a window on the Android host we target.
// Submit navigates to oauth.vk.ru/blank.html#hashes=… (same intercept as VK OAuth).

package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	hashFormDoneURL    = "https://oauth.vk.ru/blank.html"
	hashFormDoneMarker = "csqtt_hashes=1"
)

func promptManualHashes(profileDir string, prefill []string, s csqttStrings) ([]string, error) {
	if profileDir == "" {
		if len(prefill) > 0 {
			return prefill, nil
		}
		return nil, fmt.Errorf("%s", s.missingHashes)
	}
	emitProgress("%s", s.hashFormProgress)
	id := fmt.Sprintf("vk-hashes-%d", time.Now().UnixNano())
	res, cancelled := runAction(profileDir, id, map[string]any{
		"type":          "webview",
		"mode":          "navigation",
		"url":           "https://m.vk.ru/",
		"urlPattern":    hashFormDoneMarker,
		"param":         "hashes",
		"urlTimeoutSec": int(vkOAuthTimeout / time.Second),
		"injectJs":      hashFormInjectJS(prefill, s),
	})
	if cancelled {
		if len(prefill) > 0 {
			return prefill, nil
		}
		return nil, fmt.Errorf("%s", s.hashFormCancelled)
	}
	parsed := parseHashFormResult(res)
	if len(parsed) == 0 {
		return prefill, nil
	}
	return parsed, nil
}

func hashFormInjectJS(prefill []string, s csqttStrings) string {
	values := make([]string, maxVkHashes)
	labels := make([]string, maxVkHashes)
	for i := 0; i < maxVkHashes; i++ {
		labels[i] = fmt.Sprintf(s.hashFormLabelFmt, i+1)
		if i < len(prefill) {
			values[i] = prefill[i]
		}
	}
	cfg, _ := json.Marshal(map[string]any{
		"title":  s.hashFormTitle,
		"hint":   s.hashFormHint,
		"ok":     s.hashFormOk,
		"done":   hashFormDoneURL,
		"values": values,
		"labels": labels,
	})
	return `(function(){
if(window.__csqttHF)return;
window.__csqttHF=1;
var p=` + string(cfg) + `;
function paint(){
  try{
    if(document.getElementById('csqtt-hf'))return;
    var rows='';
    for(var i=0;i<p.labels.length;i++){
      var v=p.values[i]||'';
      rows+='<label>'+p.labels[i]+'<input id="h'+i+'" value="'+String(v).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;')+'" autocomplete="off" autocapitalize="off" spellcheck="false"></label>';
    }
    var html='<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1"><style>'
      +'body{font-family:sans-serif;margin:0;padding:16px;background:#111;color:#eee}'
      +'h1{font-size:18px;margin:0 0 8px}p{font-size:13px;opacity:.8;margin:0 0 12px}'
      +'label{display:block;font-size:12px;margin:0 0 8px}input{width:100%;box-sizing:border-box;padding:10px;margin-top:4px;border-radius:8px;border:1px solid #444;background:#1c1c1c;color:#fff}'
      +'button{width:100%;margin-top:12px;padding:12px;border:0;border-radius:8px;background:#4caf50;color:#fff;font-weight:700;font-size:16px}'
      +'</style></head><body><div id="csqtt-hf"><h1>'+p.title+'</h1><p>'+p.hint+'</p>'+rows
      +'<button type="button" id="csqtt-go">'+p.ok+'</button></div></body></html>';
    try{document.open();document.write(html);document.close();}catch(e1){document.documentElement.innerHTML=html;}
    var go=document.getElementById('csqtt-go');
    if(go) go.onclick=function(){
      var hs=[];
      for(var i=0;i<p.labels.length;i++){
        var el=document.getElementById('h'+i);
        var t=el&&el.value?String(el.value).replace(/^\s+|\s+$/g,''):'';
        if(t) hs.push(t);
      }
      location.replace(p.done+'?csqtt_hashes=1&hashes='+encodeURIComponent(hs.join(' ')));
    };
  }catch(e){}
}
paint();
setInterval(paint,400);
})();`
}

func parseHashFormResult(res string) []string {
	res = strings.TrimSpace(res)
	if res == "" || strings.EqualFold(res, "CANCELLED") {
		return nil
	}
	if h := extractHashesParam(res); h != "" {
		return uniqHashes([]string{h})
	}
	var obj map[string]any
	if json.Unmarshal([]byte(res), &obj) == nil {
		if h := fmt.Sprint(obj["hashes"]); h != "" && h != "<nil>" {
			return uniqHashes([]string{h})
		}
		raw := make([]string, 0, maxVkHashes)
		for i := 1; i <= maxVkHashes; i++ {
			raw = append(raw, fmt.Sprint(obj[fmt.Sprintf("hash%d", i)]))
		}
		return uniqHashes(raw)
	}
	return uniqHashes([]string{res})
}

func extractHashesParam(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || s == "<nil>" {
		return ""
	}
	rest := ""
	for _, sep := range []string{"?hashes=", "&hashes=", "#hashes="} {
		if i := strings.Index(s, sep); i >= 0 {
			rest = s[i+len(sep):]
			break
		}
	}
	if rest == "" && strings.HasPrefix(s, "hashes=") {
		rest = s[len("hashes="):]
	}
	if rest == "" {
		return ""
	}
	if j := strings.IndexAny(rest, "&?#"); j >= 0 {
		rest = rest[:j]
	}
	if u, err := url.QueryUnescape(rest); err == nil && strings.TrimSpace(u) != "" {
		rest = u
	}
	return strings.TrimSpace(rest)
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

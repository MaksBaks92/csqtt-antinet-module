package main

import (
	"strings"
	"testing"
)

// Форма, которой VK завершает implicit flow: редирект на VK_OAUTH_REDIRECT_URI с токеном во
// ФРАГМЕНТЕ. Её ловит апстримный VkAuthWebViewManager, её же ловит правило §2.7 (`urlPattern`
// blank.html + `param` access_token), поэтому разбирать её модуль обязан.
func TestParseVkAccessTokenFromRedirectFragment(t *testing.T) {
	const tok = "vk1.a.abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"
	raw := "https://oauth.vk.ru/blank.html#access_token=" + tok + "&expires_in=0&user_id=1"
	got, err := parseVkAccessToken(raw)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != tok {
		t.Fatalf("got %q", got)
	}
}

func TestParseVkAccessTokenFromQuery(t *testing.T) {
	const tok = "vk1.a.abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"
	got, err := parseVkAccessToken("https://oauth.vk.ru/blank.html?access_token=" + tok + "&expires_in=0")
	if err != nil || got != tok {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestParseVkAccessTokenBare(t *testing.T) {
	const tok = "vk1.a.abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"
	got, err := parseVkAccessToken(tok)
	if err != nil || got != tok {
		t.Fatalf("got %q err %v", got, err)
	}
}

// РЕАЛЬНАЯ форма ответа хоста: результат действия приходит конвертом своего типа, а не голым
// значением. Ради этого теста фикс и существует — без него токен доезжал и молча выбрасывался
// («empty access_token» при успешной авторизации), а вход в VK шёл по кругу бесконечно.
func TestParseVkAccessTokenFromHostEnvelope(t *testing.T) {
	const tok = "vk1.a.abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"
	got, err := parseVkAccessToken(`{"value":"` + tok + `","type":"webview"}`)
	if err != nil || got != tok {
		t.Fatalf("got %q err %v", got, err)
	}
	// Конверт, где хост отдал не голый параметр, а весь адрес редиректа (совместимость правила с
	// хостом, извлекающим URL целиком): разбор обязан вытащить токен и отсюда.
	got, err = parseVkAccessToken(`{"value":"https://oauth.vk.ru/blank.html#access_token=` + tok + `&user_id=1","type":"webview"}`)
	if err != nil || got != tok {
		t.Fatalf("url-in-envelope: got %q err %v", got, err)
	}
	// Конверт без значения — это отсутствие токена, а не токен: молчаливого успеха быть не должно.
	if _, err := parseVkAccessToken(`{"value":"","type":"webview"}`); err == nil {
		t.Fatal("пустой value обязан быть ошибкой")
	}
}

func TestParseVkAccessTokenCancelled(t *testing.T) {
	if _, err := parseVkAccessToken("CANCELLED"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := parseVkAccessToken(""); err == nil {
		t.Fatal("expected error")
	}
}

// Правило, которое модуль отдаёт хосту, обязано вести на НАСТОЯЩИЙ VK и ловить апстримный
// redirect_uri: именно подмена этих двух значений на loopback и делала вход непроходимым.
func TestVkOAuthRuleTargetsUpstreamVK(t *testing.T) {
	if !strings.HasPrefix(vkOAuthAuthURL, "https://oauth.vk.ru/authorize?") {
		t.Fatalf("authorize URL не апстримный: %q", vkOAuthAuthURL)
	}
	for _, part := range []string{"client_id=7793118", "scope=1073737727", "response_type=token", "oauth.vk.ru%2Fblank.html"} {
		if !strings.Contains(vkOAuthAuthURL, part) {
			t.Fatalf("authorize URL без %q", part)
		}
	}
	if vkLoginURL != "https://vk.ru/" {
		t.Fatalf("LOGIN URL=%q want https://vk.ru/", vkLoginURL)
	}
	if strings.Contains(vkOAuthAuthURL, "127.0.0.1") || strings.Contains(vkLoginURL, "127.0.0.1") {
		t.Fatal("в правило просочился loopback")
	}
	if vkOAuthRedirectMark != "blank.html" {
		t.Fatalf("urlPattern=%q, а VK уводит на blank.html", vkOAuthRedirectMark)
	}
	js := vkOAuthLoginThenTokenJS(vkOAuthAuthURL)
	for _, part := range []string{"remixsid", "/feed", "Лента", "location.replace", "oauth.vk.ru/authorize", "client_id=7793118"} {
		if !strings.Contains(js, part) {
			t.Fatalf("injectJs без %q", part)
		}
	}
	if strings.Contains(js, "127.0.0.1") {
		t.Fatal("injectJs с loopback")
	}
}

func TestNextEngineIdentityPrefersSetting(t *testing.T) {
	st := savedState{DeviceID: "saved-id"}
	id, gen, salt := nextEngineIdentity(map[string]string{
		"SETTING_deviceId": "android-id-from-csqtt",
		"DEVICE_ID":        "antinet-hwid",
	}, &st)
	if id != "android-id-from-csqtt" {
		t.Fatalf("id=%q", id)
	}
	if gen != 1 || salt == "" || st.DeviceID != id {
		t.Fatalf("gen=%d salt=%q saved=%q", gen, salt, st.DeviceID)
	}
	if src := persistedDeviceSource(map[string]string{
		"SETTING_deviceId": id,
		"DEVICE_ID":        "antinet-hwid",
	}, id); src != "setting" {
		t.Fatalf("src=%q", src)
	}
}

func TestNextEngineIdentityUsesHostWhenSettingEmpty(t *testing.T) {
	st := savedState{}
	id, _, _ := nextEngineIdentity(map[string]string{
		"DEVICE_ID": "antinet-hwid",
	}, &st)
	if id != "antinet-hwid" {
		t.Fatalf("id=%q", id)
	}
	if src := persistedDeviceSource(map[string]string{"DEVICE_ID": "antinet-hwid"}, id); src != "antinet" {
		t.Fatalf("src=%q", src)
	}
}

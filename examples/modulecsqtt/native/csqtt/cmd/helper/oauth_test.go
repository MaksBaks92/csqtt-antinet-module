package main

import (
	"strings"
	"testing"
)

func TestParseVkAccessTokenFromLoopbackCallback(t *testing.T) {
	const tok = "vk1.a.abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"
	raw := vkOAuthDoneURLForTest(41217) + "?access_token=" + tok + "&expires_in=0"
	got, err := parseVkAccessTokenFromCallbackURL(raw)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != tok {
		t.Fatalf("got %q", got)
	}
}

func TestParseVkAccessTokenFromHoistedURL(t *testing.T) {
	const tok = "vk1.a.abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"
	got, err := parseVkAccessToken("https://oauth.vk.com/blank.html?csqtt_ok=1&access_token=" + tok + "&expires_in=0")
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

func TestParseVkAccessTokenCancelled(t *testing.T) {
	if _, err := parseVkAccessToken("CANCELLED"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := parseVkAccessToken(""); err == nil {
		t.Fatal("expected error")
	}
}

func TestVkOAuthProxyJSHasLoopbackMarker(t *testing.T) {
	done := vkOAuthDoneURLForTest(50999)
	js := vkOAuthProxyInjectJS("http://127.0.0.1:50999", done, "")
	for _, part := range []string{vkOAuthCallbackPath, "access_token=", "127.0.0.1:50999", "pollStatus"} {
		if !strings.Contains(js, part) {
			t.Fatalf("oauth inject JS missing %q", part)
		}
	}
}

func TestStartVkOAuthCallbackServer(t *testing.T) {
	doneURL, stop, err := startVkOAuthCallbackServer()
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if !strings.Contains(doneURL, vkOAuthCallbackPath) {
		t.Fatalf("doneURL=%q", doneURL)
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

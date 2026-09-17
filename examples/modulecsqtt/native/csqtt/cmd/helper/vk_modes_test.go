package main

import "testing"

func TestNormalizeVkModes(t *testing.T) {
	cases := []struct {
		hashIn, authIn string
		wantHash       string
		wantAuth       string
	}{
		{"manual", "vkcalls", "manual", "vkcalls"},
		{"manual", "", "manual", "vkcalls"},
		{"manual", "legacy", "manual", "legacy"},
		{"manual", "captcha", "manual", "legacy"},
		// Явный Ручной не переписываем в Авто ВК (движок не умеет auto_js creds + manual hashes).
		{"manual", "auto_js", "manual", "vkcalls"},
		{"auto_api", "vkcalls", "auto_api", "vkcalls"},
		{"auto_api", "legacy", "auto_api", "legacy"},
		// Авто ВК по хешам поднимает и креды на аккаунт.
		{"auto_js", "vkcalls", "auto_js", "auto_js"},
		{"auto_js", "legacy", "auto_js", "auto_js"},
		// Авто ВК по кредам фиксирует хеши на Авто ВК (если хеши не Ручной).
		{"auto_api", "auto_js", "auto_js", "auto_js"},
	}
	for _, tc := range cases {
		h, a := normalizeVkModes(tc.hashIn, tc.authIn)
		if h != tc.wantHash || a != tc.wantAuth {
			t.Fatalf("normalizeVkModes(%q,%q)=(%q,%q), want (%q,%q)",
				tc.hashIn, tc.authIn, h, a, tc.wantHash, tc.wantAuth)
		}
	}
}

func TestNeedsVkOAuth(t *testing.T) {
	if needsVkOAuth("manual", "vkcalls") || needsVkOAuth("manual", "legacy") {
		t.Fatal("manual+guest/legacy must not require OAuth")
	}
	h, a := normalizeVkModes("manual", "auto_js")
	if needsVkOAuth(h, a) {
		t.Fatalf("manual+Авто ВК must normalize to no-OAuth path, got %s/%s", h, a)
	}
	if !needsVkOAuth("auto_api", "vkcalls") || !needsVkOAuth("auto_js", "auto_js") {
		t.Fatal("auto hash/auth must require OAuth")
	}
}

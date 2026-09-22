package main

import "testing"

func TestIdleSettings(t *testing.T) {
	cases := []struct {
		name      string
		cfg       map[string]string
		workers   int
		wantKeep  int
		wantAfter int
	}{
		{"unset → engine defaults", map[string]string{}, 27, -1, 0},
		{"explicit", map[string]string{"SETTING_idleWorkers": "3", "SETTING_idleAfterSec": "300"}, 27, 3, 300},
		{"zero disables", map[string]string{"SETTING_idleWorkers": "0"}, 27, 0, 0},
		{"clamped to workers", map[string]string{"SETTING_idleWorkers": "50"}, 27, 27, 0},
		{"unknown worker total → no clamp", map[string]string{"SETTING_idleWorkers": "50"}, 0, 50, 0},
		{"garbage ignored", map[string]string{"SETTING_idleWorkers": "x", "SETTING_idleAfterSec": "-5"}, 27, -1, 0},
	}
	for _, tc := range cases {
		keep, after := idleSettings(tc.cfg, tc.workers)
		if keep != tc.wantKeep || after != tc.wantAfter {
			t.Errorf("%s: got (%d, %d), want (%d, %d)", tc.name, keep, after, tc.wantKeep, tc.wantAfter)
		}
	}
}

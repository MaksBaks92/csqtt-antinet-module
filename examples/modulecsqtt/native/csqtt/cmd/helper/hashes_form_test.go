package main

import "testing"

func TestParseHashFormResult(t *testing.T) {
	got := parseHashFormResult(`{"hash1":"aaa","hash2":"bbb","hash3":"","hash4":"aaa"}`)
	if len(got) != 2 || got[0] != "aaa" || got[1] != "bbb" {
		t.Fatalf("got %#v", got)
	}
	fromURL := parseHashFormResult("https://oauth.vk.ru/blank.html#hashes=one+two")
	if len(fromURL) != 2 || fromURL[0] != "one" || fromURL[1] != "two" {
		t.Fatalf("url got %#v", fromURL)
	}
	fromQuery := parseHashFormResult("https://oauth.vk.ru/blank.html?csqtt_hashes=1&hashes=one+two")
	if len(fromQuery) != 2 || fromQuery[0] != "one" || fromQuery[1] != "two" {
		t.Fatalf("query got %#v", fromQuery)
	}
	if parseHashFormResult("") != nil && len(parseHashFormResult("")) != 0 {
		t.Fatal("empty should be empty")
	}
	if parseHashFormResult("CANCELLED") != nil && len(parseHashFormResult("CANCELLED")) != 0 {
		t.Fatal("cancelled should be empty")
	}
}

func TestUniqHashesSkipsNil(t *testing.T) {
	got := uniqHashes([]string{"<nil>", "abc", ""})
	if len(got) != 1 || got[0] != "abc" {
		t.Fatalf("got %#v", got)
	}
}

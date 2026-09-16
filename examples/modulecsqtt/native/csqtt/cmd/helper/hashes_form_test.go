package main

import "testing"

func TestParseHashFormResult(t *testing.T) {
	got := parseHashFormResult(`{"hash1":"aaa","hash2":"bbb","hash3":"","hash4":"aaa"}`)
	if len(got) != 2 || got[0] != "aaa" || got[1] != "bbb" {
		t.Fatalf("got %#v", got)
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

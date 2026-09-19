package main

import "testing"

func TestParseHashFormResult(t *testing.T) {
	// Боевая форма ответа хоста на `type: "form"` (MODULE_API §2.7): значения в конверте `values`.
	wrapped := parseHashFormResult(`{"type":"form","values":{"hash1":"aaa","hash2":"bbb","hash3":"","hash4":"aaa"}}`)
	if len(wrapped) != 2 || wrapped[0] != "aaa" || wrapped[1] != "bbb" {
		t.Fatalf("wrapped got %#v", wrapped)
	}
	// Плоский объект без конверта — тоже принимается: разбор не должен зависеть от того,
	// завернул ли отправитель значения.
	flat := parseHashFormResult(`{"hash1":"aaa","hash2":"bbb"}`)
	if len(flat) != 2 || flat[0] != "aaa" || flat[1] != "bbb" {
		t.Fatalf("flat got %#v", flat)
	}
	// Одна строка с несколькими хешами (вставка из буфера) разбирается тем же splitHashes.
	plain := parseHashFormResult("one two")
	if len(plain) != 2 || plain[0] != "one" || plain[1] != "two" {
		t.Fatalf("plain got %#v", plain)
	}
	if len(parseHashFormResult("")) != 0 {
		t.Fatal("empty should be empty")
	}
	if len(parseHashFormResult("CANCELLED")) != 0 {
		t.Fatal("cancelled should be empty")
	}
}

func TestUniqHashesSkipsNil(t *testing.T) {
	got := uniqHashes([]string{"<nil>", "abc", ""})
	if len(got) != 1 || got[0] != "abc" {
		t.Fatalf("got %#v", got)
	}
}

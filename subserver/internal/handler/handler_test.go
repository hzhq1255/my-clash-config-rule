package handler

import (
	"bytes"
	"compress/gzip"
	"io"
	"testing"
)

func TestSplitExtendNodes(t *testing.T) {
	got := splitExtendNodes("  vmess://a \n\n ss://b  \n")
	if len(got) != 2 {
		t.Fatalf("len(splitExtendNodes()) = %d, want 2", len(got))
	}
	if got[0] != "vmess://a" || got[1] != "ss://b" {
		t.Fatalf("splitExtendNodes() = %#v", got)
	}
}

func TestGzipData(t *testing.T) {
	encoded, err := gzipData([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}

	reader, err := gzip.NewReader(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != "hello" {
		t.Fatalf("decoded gzip = %q, want hello", string(decoded))
	}
}

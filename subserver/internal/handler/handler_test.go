package handler

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
	"os"
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

func TestSplitSubscriptionURLs(t *testing.T) {
	got := splitSubscriptionURLs(" https://a.example/sub \n\n https://b.example/sub \n")
	if len(got) != 2 {
		t.Fatalf("len(splitSubscriptionURLs()) = %d, want 2", len(got))
	}
	if got[0] != "https://a.example/sub" || got[1] != "https://b.example/sub" {
		t.Fatalf("splitSubscriptionURLs() = %#v", got)
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

func TestDecodeSubContent(t *testing.T) {
	t.Run("accepts vmess link", func(t *testing.T) {
		input := "vmess://abc"
		got, err := decodeSubContent(input)
		if err != nil {
			t.Fatal(err)
		}
		if got != input {
			t.Fatalf("decodeSubContent() = %q, want %q", got, input)
		}
	})

	t.Run("accepts raw base64 payload", func(t *testing.T) {
		input := "vmess://xyz"
		encoded := base64.StdEncoding.EncodeToString([]byte(input))
		got, err := decodeSubContent(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if got != input {
			t.Fatalf("decodeSubContent() = %q, want %q", got, input)
		}
	})
}

func TestStripAnyTLSSkipCertVerify(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "normal-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	input := `proxies:
  - name: anytls-node
    type: anytls
    server: example.com
    port: 443
    skip-cert-verify: false
  - name: vless-node
    type: vless
    server: example.com
    port: 443
    skip-cert-verify: false
`
	if _, err := file.WriteString(input); err != nil {
		t.Fatal(err)
	}

	if err := stripAnyTLSSkipCertVerify(file.Name()); err != nil {
		t.Fatal(err)
	}

	output, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	text := string(output)
	if !bytes.Contains(output, []byte("type: anytls")) {
		t.Fatal("anytls node missing after post process")
	}
	if !bytes.Contains(output, []byte("type: vless")) {
		t.Fatal("vless node missing after post process")
	}
	if bytes.Contains(output, []byte("type: anytls\n    server: example.com\n    port: 443\n    skip-cert-verify: false")) {
		t.Fatal("anytls skip-cert-verify should be removed")
	}
	if !bytes.Contains(output, []byte("type: vless")) || !bytes.Contains(output, []byte("skip-cert-verify: false")) {
		t.Fatalf("expected vless skip-cert-verify to remain, got:\n%s", text)
	}
}

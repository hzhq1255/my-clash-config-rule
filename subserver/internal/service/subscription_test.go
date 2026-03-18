package service

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestReplaceDomain(t *testing.T) {
	got := replaceDomain("https://old.example.com/api/sub?token=1", "new.example.com")
	want := "https://new.example.com/api/sub?token=1"
	if got != want {
		t.Fatalf("replaceDomain() = %q, want %q", got, want)
	}
}

func TestProcessVmessNodeFillsSNIFromHost(t *testing.T) {
	svc := NewSubscriptionService(nil, "")
	raw := map[string]string{
		"v":    "2",
		"ps":   "test",
		"add":  "server.example.com",
		"port": "443",
		"id":   "uuid",
		"aid":  "0",
		"scy":  "auto",
		"net":  "ws",
		"type": "none",
		"host": "host.example.com",
		"path": "/ws",
		"tls":  "tls",
		"sni":  "",
	}
	data, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	node := "vmess://" + base64.StdEncoding.EncodeToString(data)

	got := svc.processVmessNode(node)
	parsed, err := base64.StdEncoding.DecodeString(got[len("vmess://"):])
	if err != nil {
		t.Fatal(err)
	}

	var decoded map[string]string
	if err := json.Unmarshal(parsed, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["sni"] != "host.example.com" {
		t.Fatalf("sni = %q, want host.example.com", decoded["sni"])
	}
}

func TestParseClashProxyLine(t *testing.T) {
	line := `- {"name":"demo","type":"vmess","server":"example.com","port":443,"uuid":"uuid","alterId":0,"cipher":"auto","tls":true,"servername":"sni.example.com","network":"ws","ws-opts":{"path":"/ws","headers":{"Host":"host.example.com"}}}`
	got := parseClashProxyLine(line)
	if got == "" {
		t.Fatal("parseClashProxyLine() returned empty result")
	}

	data, err := base64.StdEncoding.DecodeString(got[len("vmess://"):])
	if err != nil {
		t.Fatal(err)
	}

	var decoded map[string]string
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["add"] != "example.com" || decoded["tls"] != "tls" || decoded["host"] != "host.example.com" {
		t.Fatalf("decoded vmess = %#v", decoded)
	}
}

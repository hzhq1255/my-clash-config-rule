package service

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/hzhq1255/my-clash-config-rule/subserver/internal/model"
)

func TestEncodeAndParseVmessNode(t *testing.T) {
	svc := NewNodeService()
	node := &model.VmessNode{
		V:    "2",
		Ps:   "demo",
		Add:  "example.com",
		Port: "443",
		ID:   "uuid",
		Aid:  "0",
		Scy:  "auto",
		Net:  "ws",
		Type: "none",
		Host: "example.com",
		Path: "/ws",
		TLS:  "tls",
		SNI:  "example.com",
	}

	link, err := svc.EncodeVmessNode(node)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := svc.ParseVmessNode(link)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Add != node.Add || parsed.SNI != node.SNI {
		t.Fatalf("parsed node = %+v, want %+v", parsed, node)
	}
}

func TestEncodeVmessNodesProducesSubscriptionBase64(t *testing.T) {
	svc := NewNodeService()
	content, err := svc.EncodeVmessNodes([]model.VmessNode{{
		V:    "2",
		Ps:   "demo",
		Add:  "example.com",
		Port: "443",
		ID:   "uuid",
	}})
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) == 0 {
		t.Fatal("decoded subscription should not be empty")
	}

	vmess := string(decoded)
	if len(vmess) < len("vmess://") || vmess[:8] != "vmess://" {
		t.Fatalf("decoded content = %q, want vmess link", vmess)
	}

	payload, err := base64.StdEncoding.DecodeString(vmess[len("vmess://"):])
	if err != nil {
		t.Fatal(err)
	}
	var node map[string]any
	if err := json.Unmarshal(payload, &node); err != nil {
		t.Fatal(err)
	}
	if node["add"] != "example.com" {
		t.Fatalf("node add = %v, want example.com", node["add"])
	}
}

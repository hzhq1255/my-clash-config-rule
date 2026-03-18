package service

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/hzhq1255/my-clash-config-rule/subserver/internal/model"
	"gopkg.in/yaml.v3"
)

// NodeService handles node parsing and processing.
type NodeService struct{}

// NewNodeService creates a new node service.
func NewNodeService() *NodeService {
	return &NodeService{}
}

// ParseVmessNode parses a vmess:// link.
func (s *NodeService) ParseVmessNode(vmessLink string) (*model.VmessNode, error) {
	if !strings.HasPrefix(vmessLink, "vmess://") {
		return nil, fmt.Errorf("not a vmess link")
	}

	encoded := strings.TrimPrefix(vmessLink, "vmess://")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}

	var node model.VmessNode
	if err := json.Unmarshal(decoded, &node); err != nil {
		return nil, fmt.Errorf("json parse failed: %w", err)
	}
	return &node, nil
}

// EncodeVmessNode encodes a vmess node to vmess:// link.
func (s *NodeService) EncodeVmessNode(node *model.VmessNode) (string, error) {
	data, err := json.Marshal(node)
	if err != nil {
		return "", fmt.Errorf("json marshal failed: %w", err)
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(data), nil
}

// EncodeVmessNodes encodes multiple vmess nodes to base64 subscription format.
func (s *NodeService) EncodeVmessNodes(nodes []model.VmessNode) (string, error) {
	links := make([]string, 0, len(nodes))
	for _, node := range nodes {
		link, err := s.EncodeVmessNode(&node)
		if err != nil {
			slog.Warn("Failed to encode node", "name", node.Ps, "error", err)
			continue
		}
		links = append(links, link)
	}

	content := strings.Join(links, "\n")
	return base64.StdEncoding.EncodeToString([]byte(content)), nil
}

// ConvertToCFIPSubscription converts a vmess link to better CF IPs output.
func (s *NodeService) ConvertToCFIPSubscription(vmessLink, fileFormat string, cfIPService *CFIPService) (string, error) {
	templateNode, err := s.ParseVmessNode(strings.TrimSpace(vmessLink))
	if err != nil {
		return "", err
	}

	ipData, err := cfIPService.GetBetterCFIPs()
	if err != nil {
		slog.Warn("Get CF IPs failed, falling back to original node", "error", err)
		return s.encodeFallback(templateNode, fileFormat)
	}

	operators := []TelecomOperator{TelecomCM, TelecomCU, TelecomCT}
	if fileFormat == "yaml" {
		payload := struct {
			Proxies []model.ClashProxy `yaml:"proxies"`
		}{
			Proxies: cfIPService.GenerateClashProxies(templateNode, ipData, operators),
		}
		out, err := yaml.Marshal(payload)
		if err != nil {
			return "", fmt.Errorf("marshal yaml: %w", err)
		}
		return string(out), nil
	}

	newNodes := cfIPService.GenerateCFIPVmessProxies(templateNode, ipData, operators)
	return s.EncodeVmessNodes(newNodes)
}

func (s *NodeService) encodeFallback(node *model.VmessNode, fileFormat string) (string, error) {
	if fileFormat == "yaml" {
		payload := struct {
			Proxies []model.ClashProxy `yaml:"proxies"`
		}{
			Proxies: []model.ClashProxy{fallbackClashProxy(node)},
		}
		out, err := yaml.Marshal(payload)
		if err != nil {
			return "", fmt.Errorf("marshal fallback yaml: %w", err)
		}
		return string(out), nil
	}
	return s.EncodeVmessNodes([]model.VmessNode{*node})
}

func fallbackClashProxy(node *model.VmessNode) model.ClashProxy {
	port := 443
	if node.Port != "" {
		if parsed, err := strconv.Atoi(node.Port); err == nil {
			port = parsed
		}
	}
	return model.ClashProxy{
		Name:           node.Ps,
		Server:         node.Add,
		Port:           port,
		Type:           "vmess",
		UUID:           node.ID,
		AlterID:        0,
		Cipher:         node.Scy,
		TLS:            node.TLS == "tls",
		SkipCertVerify: false,
		ServerName:     node.SNI,
		Network:        node.Net,
		WSOpts: model.WSOptions{
			Path: node.Path,
			Headers: map[string]string{
				"Host": node.Host,
			},
		},
	}
}

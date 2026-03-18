package service

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/hzhq1255/my-clash-config-rule/subserver/internal/model"
)

// NodeService handles node parsing and processing
type NodeService struct{}

// NewNodeService creates a new node service
func NewNodeService() *NodeService {
	return &NodeService{}
}

// ParseVmessNode parses a vmess:// link
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

// EncodeVmessNode encodes a vmess node to vmess:// link
func (s *NodeService) EncodeVmessNode(node *model.VmessNode) (string, error) {
	data, err := json.Marshal(node)
	if err != nil {
		return "", fmt.Errorf("json marshal failed: %w", err)
	}

	encoded := base64.StdEncoding.EncodeToString(data)
	return "vmess://" + encoded, nil
}

// EncodeVmessNodes encodes multiple vmess nodes to base64 subscription format
func (s *NodeService) EncodeVmessNodes(nodes []model.VmessNode) (string, error) {
	var links []string
	for _, node := range nodes {
		link, err := s.EncodeVmessNode(&node)
		if err != nil {
			slog.Warn("Failed to encode node", "name", node.Ps, "error", err)
			continue
		}
		links = append(links, link)
	}

	content := strings.Join(links, "\n")
	encoded := base64.StdEncoding.EncodeToString([]byte(content))
	return encoded, nil
}

// ParseSubscription parses a base64 encoded subscription
func (s *NodeService) ParseSubscription(subscription string) ([]model.VmessNode, error) {
	decoded, err := base64.StdEncoding.DecodeString(subscription)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}

	lines := strings.Split(string(decoded), "\n")
	var nodes []model.VmessNode

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		node, err := s.ParseVmessNode(line)
		if err != nil {
			slog.Warn("Failed to parse node", "link", line, "error", err)
			continue
		}
		nodes = append(nodes, *node)
	}

	return nodes, nil
}

// ConvertToCFIPSubscription converts vmess subscription to CF better IP subscription
func (s *NodeService) ConvertToCFIPSubscription(subscription string, fileFormat string, cfIPService *CFIPService) (string, error) {
	nodes, err := s.ParseSubscription(subscription)
	if err != nil {
		return "", err
	}

	if len(nodes) == 0 {
		return "", fmt.Errorf("no valid nodes found")
	}

	// Use first node as template
	templateNode := nodes[0]

	ipData, err := cfIPService.GetBetterCFIPs()
	if err != nil {
		return "", fmt.Errorf("get CF IPs failed: %w", err)
	}

	operators := []TelecomOperator{TelecomCM, TelecomCU, TelecomCT}

	if fileFormat == "yaml" {
		// Generate Clash YAML format
		proxies := cfIPService.GenerateClashProxies(&templateNode, ipData, operators)
		// TODO: Generate YAML output
		return fmt.Sprintf("proxies:\n  # %d proxies", len(proxies)), nil
	}

	// Generate vmess subscription format
	newNodes := cfIPService.GenerateCFIPVmessProxies(&templateNode, ipData, operators)
	return s.EncodeVmessNodes(newNodes)
}

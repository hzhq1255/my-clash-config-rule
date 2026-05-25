package service

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hzhq1255/my-clash-config-rule/subserver/internal/model"
)

var excludeNodePattern = regexp.MustCompile(`流量|过期时间|地址|故障`)

// SubscriptionService handles subscription operations.
type SubscriptionService struct {
	client *http.Client
}

// NewSubscriptionService creates a new subscription service.
func NewSubscriptionService() *SubscriptionService {
	return &SubscriptionService{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// MergeSubContent merges direct subscription contents from configured URLs.
func (s *SubscriptionService) MergeSubContent(subURLs []string, extendNodes []string) (*model.SubscriptionContent, error) {
	if len(subURLs) == 0 {
		return nil, fmt.Errorf("no subscription URLs configured")
	}

	var nodeList []string
	var userInfo string

	for _, subURL := range subURLs {
		req, err := http.NewRequest(http.MethodGet, subURL, nil)
		if err != nil {
			slog.Error("Create request failed", "url", subURL, "error", err)
			continue
		}

		resp, err := s.client.Do(req)
		if err != nil {
			slog.Error("Get subscription failed", "url", subURL, "error", err)
			continue
		}

		if userInfo == "" {
			userInfo = resp.Header.Get("Subscription-Userinfo")
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			slog.Error("Read subscription failed", "url", subURL, "error", err)
			continue
		}

		decodedBody, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
		if err != nil {
			decodedBody = body
		}

		nodeList = append(nodeList, s.extractNodes(string(decodedBody))...)
	}

	if len(nodeList) == 0 {
		return nil, fmt.Errorf("no subscription nodes found")
	}

	filtered := make([]string, 0, len(nodeList)+len(extendNodes))
	filtered = append(filtered, extendNodes...)
	for _, node := range nodeList {
		unescaped, err := url.PathUnescape(node)
		if err != nil {
			unescaped = node
		}
		if excludeNodePattern.MatchString(unescaped) {
			continue
		}
		filtered = append(filtered, s.processNode(node))
	}

	mergedContent := strings.Join(filtered, "\n")
	return &model.SubscriptionContent{
		Content:              base64.StdEncoding.EncodeToString([]byte(mergedContent)),
		SubscriptionUserinfo: userInfo,
	}, nil
}

func (s *SubscriptionService) extractNodes(decoded string) []string {
	var nodes []string
	scanner := bufio.NewScanner(strings.NewReader(decoded))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		switch {
		case strings.HasPrefix(line, "vmess://"),
			strings.HasPrefix(line, "trojan://"),
			strings.HasPrefix(line, "ss://"),
			strings.HasPrefix(line, "ssr://"),
			strings.HasPrefix(line, "vless://"),
			strings.HasPrefix(line, "anytls://"),
			strings.HasPrefix(line, "hy2://"),
			strings.HasPrefix(line, "hysteria2://"):
			nodes = append(nodes, line)
		case strings.HasPrefix(line, "- {"):
			if vmessNode := parseClashProxyLine(line); vmessNode != "" {
				nodes = append(nodes, vmessNode)
			}
		}
	}
	return nodes
}

func parseClashProxyLine(line string) string {
	payload := strings.TrimSpace(strings.TrimPrefix(line, "- "))
	var proxy map[string]any
	if err := json.Unmarshal([]byte(payload), &proxy); err != nil {
		return ""
	}
	if fmt.Sprint(proxy["type"]) != "vmess" {
		return ""
	}

	node := map[string]string{
		"v":    "2",
		"ps":   stringValue(proxy["name"]),
		"add":  stringValue(proxy["server"]),
		"port": normalizeNumericField(proxy["port"]),
		"id":   stringValue(proxy["uuid"]),
		"aid":  normalizeNumericField(proxy["alterId"]),
		"scy":  stringValue(proxy["cipher"]),
		"net":  stringValue(proxy["network"]),
		"type": "none",
		"host": "",
		"path": "",
		"tls":  "",
		"sni":  stringValue(proxy["servername"]),
		"alpn": stringValue(proxy["alpn"]),
		"fp":   stringValue(proxy["client-fingerprint"]),
	}
	if node["net"] == "" {
		node["net"] = "tcp"
	}

	if tls, ok := proxy["tls"].(bool); ok && tls {
		node["tls"] = "tls"
	}
	if wsOpts, ok := proxy["ws-opts"].(map[string]any); ok {
		if path, ok := wsOpts["path"]; ok {
			node["path"] = stringValue(path)
		}
		if headers, ok := wsOpts["headers"].(map[string]any); ok {
			if host, ok := headers["Host"]; ok {
				node["host"] = stringValue(host)
			}
		}
	}
	if node["host"] == "" {
		node["host"] = stringValue(proxy["host"])
	}

	data, err := json.Marshal(node)
	if err != nil {
		return ""
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(data)
}

func normalizeNumericField(v any) string {
	if v == nil {
		return ""
	}
	switch value := v.(type) {
	case string:
		return value
	case float64:
		return strconv.Itoa(int(value))
	case int:
		return strconv.Itoa(value)
	default:
		return fmt.Sprint(v)
	}
}

func stringValue(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		if s == "<nil>" {
			return ""
		}
		return s
	}
	value := fmt.Sprint(v)
	if value == "<nil>" {
		return ""
	}
	return value
}

func (s *SubscriptionService) processNode(node string) string {
	switch {
	case strings.HasPrefix(node, "vmess://"):
		return s.processVmessNode(node)
	case strings.HasPrefix(node, "anytls://"):
		return normalizeAnyTLSNode(node)
	case strings.HasPrefix(node, "hy2://"), strings.HasPrefix(node, "hysteria2://"):
		return normalizeHysteria2Node(node)
	default:
		return node
	}
}

func (s *SubscriptionService) processVmessNode(node string) string {
	encoded := strings.TrimPrefix(node, "vmess://")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return node
	}

	var vmess map[string]any
	if err := json.Unmarshal(decoded, &vmess); err != nil {
		return node
	}

	sni, _ := vmess["sni"].(string)
	host, _ := vmess["host"].(string)
	if (sni == "" || strings.EqualFold(sni, "null")) && host != "" && !strings.EqualFold(host, "null") {
		vmess["sni"] = host
		newJSON, err := json.Marshal(vmess)
		if err != nil {
			return node
		}
		return "vmess://" + base64.StdEncoding.EncodeToString(newJSON)
	}

	return node
}

func normalizeHysteria2Node(node string) string {
	node = strings.Replace(node, "hy2://", "hysteria2://", 1)
	node = strings.Replace(node, "/?", "?", 1)
	return node
}

func normalizeAnyTLSNode(node string) string {
	parsed, err := url.Parse(node)
	if err != nil {
		return node
	}

	query := parsed.Query()
	sni := query.Get("sni")
	if sni != "" && query.Get("peer") == "" {
		query.Set("peer", sni)
		parsed.RawQuery = query.Encode()
	}

	return parsed.String()
}

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

	"github.com/hzhq1255/my-clash-config-rule/subserver/internal/model"
)

var v2RayAnchorPattern = regexp.MustCompile(`(?is)<a[^>]*data-clipboard-text="([^"]+)"[^>]*>.*?V2Ray.*?</a>`)
var excludeNodePattern = regexp.MustCompile(`流量|过期时间|地址|故障`)

// SubscriptionService handles subscription operations.
type SubscriptionService struct {
	authService *AuthService
	domain      string
}

// NewSubscriptionService creates a new subscription service.
func NewSubscriptionService(authService *AuthService, domain string) *SubscriptionService {
	return &SubscriptionService{
		authService: authService,
		domain:      domain,
	}
}

// GetSubUrls retrieves subscription URLs from the user page.
func (s *SubscriptionService) GetSubUrls() ([]string, error) {
	userURL := fmt.Sprintf("https://%s/user", s.domain)
	req, err := http.NewRequest(http.MethodGet, userURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := s.authService.DoRequest(req)
	if err != nil {
		return nil, fmt.Errorf("get user page: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	matches := v2RayAnchorPattern.FindAllStringSubmatch(string(body), -1)
	if len(matches) == 0 {
		return nil, fmt.Errorf("no subscription URLs found")
	}

	urls := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		urls = append(urls, match[1])
		slog.Info("Found V2Ray subscription", "url", match[1])
	}

	if len(urls) == 0 {
		return nil, fmt.Errorf("no valid subscription URLs found")
	}
	return urls, nil
}

// MergeSubContent merges multiple subscription contents.
func (s *SubscriptionService) MergeSubContent(subURLs []string, extendNodes []string, useDomain bool) (*model.SubscriptionContent, error) {
	var nodeList []string
	var userInfo string

	for _, rawURL := range subURLs {
		subURL := rawURL
		if useDomain {
			subURL = replaceDomain(subURL, s.domain)
			slog.Info("Replaced subscription domain", "url", subURL)
		}

		req, err := http.NewRequest(http.MethodGet, subURL, nil)
		if err != nil {
			slog.Error("Create request failed", "url", subURL, "error", err)
			continue
		}

		resp, err := s.authService.DoRequest(req)
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
		filtered = append(filtered, s.processVmessNode(node))
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

func replaceDomain(rawURL, newDomain string) string {
	if !strings.HasPrefix(rawURL, "https://") {
		return rawURL
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	parsed.Host = newDomain
	return parsed.String()
}

func (s *SubscriptionService) processVmessNode(node string) string {
	if !strings.HasPrefix(node, "vmess://") {
		return node
	}

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

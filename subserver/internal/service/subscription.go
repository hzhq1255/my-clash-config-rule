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
	"strings"

	"github.com/hzhq1255/my-clash-config-rule/subserver/internal/model"
)

// SubscriptionService handles subscription operations
type SubscriptionService struct {
	authService *AuthService
	domain      string
}

// NewSubscriptionService creates a new subscription service
func NewSubscriptionService(authService *AuthService, domain string) *SubscriptionService {
	return &SubscriptionService{
		authService: authService,
		domain:      domain,
	}
}

// GetSubUrls retrieves subscription URLs from user page
// Uses regex to parse HTML since we don't want heavy dependencies
func (s *SubscriptionService) GetSubUrls() ([]string, error) {
	userURL := fmt.Sprintf("https://%s/user", s.domain)

	req, err := http.NewRequest("GET", userURL, nil)
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

	// Use regex to find data-clipboard-text attributes containing V2Ray links
	re := regexp.MustCompile(`data-clipboard-text="([^"]*V2Ray[^"]*)"`)
	matches := re.FindAllStringSubmatch(string(body), -1)

	if len(matches) == 0 {
		return nil, fmt.Errorf("no subscription URLs found")
	}

	var urls []string
	for _, match := range matches {
		if len(match) > 1 {
			urls = append(urls, match[1])
			slog.Info("Found V2Ray subscription", "url", match[1])
		}
	}

	return urls, nil
}

// MergeSubContent merges multiple subscription contents
func (s *SubscriptionService) MergeSubContent(subUrls []string, extendNodes []string, useDomain bool) (*model.SubscriptionContent, error) {
	var nodeList []string
	var userInfo string

	for _, subURL := range subUrls {
		// Optionally replace domain
		if useDomain {
			parsedURL, err := url.Parse(subURL)
			if err == nil {
				parsedURL.Host = s.domain
				subURL = parsedURL.String()
				slog.Info("Replaced subscription domain", "url", subURL)
			}
		}

		req, err := http.NewRequest("GET", subURL, nil)
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

		// Read response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			slog.Error("Read response body failed", "error", err)
			resp.Body.Close()
			continue
		}
		resp.Body.Close()

		// Try base64 decode
		decodedBytes, err := base64.StdEncoding.DecodeString(string(body))
		if err != nil {
			// Not base64, use raw content
			decodedBytes = body
		}

		// Split by lines
		scanner := bufio.NewScanner(strings.NewReader(string(decodedBytes)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				nodeList = append(nodeList, line)
			}
		}
	}

	// Filter nodes
	nodeList = s.filterNodes(nodeList)

	// Add extend nodes at the beginning
	if len(extendNodes) > 0 {
		nodeList = append(extendNodes, nodeList...)
		slog.Info("Added extend nodes", "count", len(extendNodes))
	}

	slog.Info("Merged subscription", "node_count", len(nodeList))

	// Encode back to base64
	mergedContent := strings.Join(nodeList, "\n")
	encodedContent := base64.StdEncoding.EncodeToString([]byte(mergedContent))

	return &model.SubscriptionContent{
		Content:                 encodedContent,
		SubscriptionUserinfo: userInfo,
	}, nil
}

// filterNodes filters out unwanted nodes
func (s *SubscriptionService) filterNodes(nodes []string) []string {
	excludePattern := regexp.MustCompile(`流量|过期时间|地址|故障`)
	var filtered []string

	for _, node := range nodes {
		// Decode URL to check content
		unescaped, err := url.PathUnescape(node)
		if err != nil {
			unescaped = node
		}

		// Process vmess nodes to fix SNI
		processedNode := s.processVmessNode(node)

		if excludePattern.MatchString(unescaped) {
			slog.Debug("Filtered out node", "node", node)
			continue
		}

		if processedNode != "" {
			filtered = append(filtered, processedNode)
		} else {
			filtered = append(filtered, node)
		}
	}

	return filtered
}

// processVmessNode processes vmess node to fix SNI field
func (s *SubscriptionService) processVmessNode(node string) string {
	if !strings.HasPrefix(node, "vmess://") {
		return node
	}

	encoded := strings.TrimPrefix(node, "vmess://")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return node
	}

	// Parse vmess config
	var vmess map[string]interface{}
	if err := json.Unmarshal(decoded, &vmess); err != nil {
		return node
	}

	// Fix SNI from host if SNI is empty
	sni, _ := vmess["sni"].(string)
	host, _ := vmess["host"].(string)

	if (sni == "" || sni == "null") && host != "" && host != "null" {
		vmess["sni"] = host
		// Re-encode
		newJSON, _ := json.Marshal(vmess)
		newEncoded := base64.StdEncoding.EncodeToString(newJSON)
		return "vmess://" + newEncoded
	}

	return node
}

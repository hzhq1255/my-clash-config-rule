package service

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/hzhq1255/my-clash-config-rule/subserver/internal/model"
)

// TelecomOperator represents telecom operator type
type TelecomOperator string

const (
	TelecomCM TelecomOperator = "CM" // China Mobile
	TelecomCU TelecomOperator = "CU" // China Unicom
	TelecomCT TelecomOperator = "CT" // China Telecom
)

// CFIPService handles Cloudflare IP operations
type CFIPService struct {
	client *http.Client
}

// NewCFIPService creates a new CF IP service
func NewCFIPService() *CFIPService {
	return &CFIPService{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// GetBetterCFIPs fetches better Cloudflare IPs from API
func (s *CFIPService) GetBetterCFIPs() (*model.IpData, error) {
	url := "https://api.vvhan.com/tool/cf_ip"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	// Set headers
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("Origin", "https://cf.vvhan.com")
	req.Header.Set("Referer", "https://cf.vvhan.com/")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var ipData model.IpData
	if err := json.Unmarshal(body, &ipData); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	slog.Info("Fetched CF IPs", "v4_count", len(ipData.Data.V4))
	return &ipData, nil
}

// FilterIPv4BySpeed filters IPv4 addresses by minimum speed
func (s *CFIPService) FilterIPv4BySpeed(ipData *model.IpData, operators []TelecomOperator, minSpeed int) []model.IpItem {
	var ips []model.IpItem

	for _, op := range operators {
		if items, ok := ipData.Data.V4[string(op)]; ok {
			for _, item := range items {
				if item.Speed >= minSpeed {
					ips = append(ips, item)
				}
			}
		}
	}

	// Sort by speed descending
	sort.Slice(ips, func(i, j int) bool {
		return ips[i].Speed > ips[j].Speed
	})

	slog.Info("Filtered CF IPs", "count", len(ips))
	return ips
}

// GroupIPv4ByName groups IPv4 addresses by name
func (s *CFIPService) GroupIPv4ByName(ips []model.IpItem) map[string][]model.IpItem {
	grouped := make(map[string][]model.IpItem)
	for _, ip := range ips {
		grouped[ip.Name] = append(grouped[ip.Name], ip)
	}
	return grouped
}

// GenerateCFIPVmessProxies generates vmess proxies with CF better IPs
func (s *CFIPService) GenerateCFIPVmessProxies(proxy *model.VmessNode, ipData *model.IpData, operators []TelecomOperator) []model.VmessNode {
	ips := s.FilterIPv4BySpeed(ipData, operators, 1000)
	grouped := s.GroupIPv4ByName(ips)

	var proxies []model.VmessNode
	for name, items := range grouped {
		for i, item := range items {
			newProxy := *proxy // Copy
			newProxy.Add = item.IP
			newProxy.Ps = fmt.Sprintf("%s-%d", name, i+1)
			proxies = append(proxies, newProxy)
		}
	}

	slog.Info("Generated CF IP vmess proxies", "count", len(proxies))
	return proxies
}

// GenerateClashProxies generates Clash proxy configurations
func (s *CFIPService) GenerateClashProxies(proxy *model.VmessNode, ipData *model.IpData, operators []TelecomOperator) []model.ClashProxy {
	ips := s.FilterIPv4BySpeed(ipData, operators, 1000)
	grouped := s.GroupIPv4ByName(ips)

	var proxies []model.ClashProxy
	for name, items := range grouped {
		for i, item := range items {
			port := 443
			if proxy.Port != "" {
				if parsed, err := strconv.Atoi(proxy.Port); err == nil {
					port = parsed
				}
			}

			proxies = append(proxies, model.ClashProxy{
				Name:           fmt.Sprintf("%s-%d", name, i+1),
				Server:         item.IP,
				Port:           port,
				Type:           "vmess",
				UUID:           proxy.ID,
				AlterID:        0,
				Cipher:         proxy.Scy,
				TLS:            proxy.TLS == "tls",
				SkipCertVerify: false,
				ServerName:     proxy.Add,
				Network:        proxy.Net,
				WSOpts: model.WSOptions{
					Path: proxy.Path,
					Headers: map[string]string{
						"Host": proxy.Host,
					},
				},
			})
		}
	}

	slog.Info("Generated Clash proxies", "count", len(proxies))
	return proxies
}

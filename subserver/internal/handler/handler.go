package handler

import (
	"bytes"
	"compress/gzip"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/hzhq1255/my-clash-config-rule/subserver/internal/config"
	"github.com/hzhq1255/my-clash-config-rule/subserver/internal/model"
	"github.com/hzhq1255/my-clash-config-rule/subserver/internal/service"
)

const (
	normalINIURL     = "https://raw.githubusercontent.com/hzhq1255/my-clash-config-rule/master/clash/config/Normal.ini"
	normalMobileURL  = "https://raw.githubusercontent.com/hzhq1255/my-clash-config-rule/master/clash/config/Normal_Mobile.ini"
)

//go:embed templates/normal_ruleset.yaml.tmpl
var normalRulesetTemplate string

type cachedSubscription struct {
	value     *model.SubscriptionContent
	expiresAt time.Time
}

// Handler holds dependencies for HTTP handlers.
type Handler struct {
	cfg                 *config.Config
	subscriptionService *service.SubscriptionService
	nodeService         *service.NodeService
	cfIPService         *service.CFIPService
	converterService    *service.ConverterService

	cacheMu          sync.Mutex
	subscriptionData *cachedSubscription
}

// New creates a new handler.
func New(
	cfg *config.Config,
	_ *service.AuthService,
	subscriptionService *service.SubscriptionService,
	nodeService *service.NodeService,
	cfIPService *service.CFIPService,
	converterService *service.ConverterService,
) *Handler {
	return &Handler{
		cfg:                 cfg,
		subscriptionService: subscriptionService,
		nodeService:         nodeService,
		cfIPService:         cfIPService,
		converterService:    converterService,
	}
}

// Routes returns all HTTP routes.
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/sub/links.txt", h.handleLinks)
	mux.HandleFunc("/sub/normal.yaml", h.handleNormalYAML)
	mux.HandleFunc("/sub/surfboard.txt", h.handleSurfboard)
	mux.HandleFunc("/sub/normal-ruleset.yaml", h.handleNormalRuleset)
	mux.HandleFunc("/sub/convert_cf_better_ips", h.handleConvertCFIPs)
	mux.HandleFunc("/health", h.handleHealth)
	return mux
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

func (h *Handler) handleLinks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}

	merged, err := h.getMergedSubscription()
	if err != nil {
		h.writeJSONError(w, http.StatusInternalServerError, err)
		return
	}

	w.Header().Set("Subscription-Userinfo", merged.SubscriptionUserinfo)
	w.Header().Set("Content-Type", "application/octet-stream; charset=utf-8")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(merged.Content)))
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=links-%d.txt", time.Now().Unix()))
	_, _ = w.Write([]byte(merged.Content))
}

func (h *Handler) handleNormalYAML(w http.ResponseWriter, r *http.Request) {
	configURL := normalINIURL
	outputName := fmt.Sprintf("normal-%d.yaml", time.Now().Unix())
	if r.URL.Query().Get("lite") == "true" {
		configURL = normalMobileURL
		outputName = fmt.Sprintf("normal-lite-%d.yaml", time.Now().Unix())
	}

	h.handleConvertedFile(w, r, convertedFileOptions{
		configName:  "clashnormal",
		outputName:  outputName,
		target:      "clash",
		contentType: "application/octet-stream; charset=utf-8",
		sourceURL:   h.internalLinksURL(),
		configURL:   configURL,
		postProcess: nil,
	})
}

func (h *Handler) handleSurfboard(w http.ResponseWriter, r *http.Request) {
	// Check if lite parameter is set
	configURL := normalINIURL
	outputName := fmt.Sprintf("surfboard-%d.txt", time.Now().Unix())
	if r.URL.Query().Get("lite") == "true" {
		configURL = normalMobileURL
		outputName = fmt.Sprintf("surfboard-lite-%d.txt", time.Now().Unix())
	}

	h.handleConvertedFile(w, r, convertedFileOptions{
		configName:  "surfboard",
		outputName:  outputName,
		target:      "surfboard",
		contentType: "application/octet-stream; charset=utf-8",
		sourceURL:   h.internalLinksURL(),
		configURL:   configURL,
		postProcess: func(path string) error {
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			// Build the managed config URL with query parameters preserved
			updatePath := "/sub/surfboard.txt"
			if r.URL.RawQuery != "" {
				updatePath = "/sub/surfboard.txt?" + r.URL.RawQuery
			}
			managedInfo := fmt.Sprintf("#!MANAGED-CONFIG %s interval=86400 strict=false", h.absoluteURL(r, "http", updatePath))
			lines := strings.Split(string(content), "\n")
			if len(lines) > 0 && strings.HasPrefix(lines[0], "#!MANAGED-CONFIG") {
				lines[0] = managedInfo
			} else {
				lines = append([]string{managedInfo}, lines...)
			}
			return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644)
		},
	})
}

func (h *Handler) handleNormalRuleset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}

	merged, err := h.getMergedSubscription()
	if err != nil {
		h.writeJSONError(w, http.StatusInternalServerError, err)
		return
	}

	tmpl, err := template.New("normal_ruleset").Parse(normalRulesetTemplate)
	if err != nil {
		h.writeJSONError(w, http.StatusInternalServerError, fmt.Errorf("parse ruleset template: %w", err))
		return
	}

	var rendered bytes.Buffer
	err = tmpl.Execute(&rendered, map[string]string{
		"SubURL":        fmt.Sprintf("https://%s/sub/links.txt", r.Host),
		"GHProxyDomain": h.cfg.GHProxyDomain,
	})
	if err != nil {
		h.writeJSONError(w, http.StatusInternalServerError, fmt.Errorf("render ruleset template: %w", err))
		return
	}

	zipped, err := gzipData(rendered.Bytes())
	if err != nil {
		h.writeJSONError(w, http.StatusInternalServerError, err)
		return
	}

	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Content-Type", "application/octet-stream; charset=utf-8")
	w.Header().Set("Subscription-Userinfo", merged.SubscriptionUserinfo)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=normal-ruleset-%d.yaml", time.Now().Unix()))
	_, _ = w.Write(zipped)
}

func (h *Handler) handleConvertCFIPs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}

	subContent := r.URL.Query().Get("sub_content")
	if subContent == "" {
		http.Error(w, "sub_content is empty", http.StatusInternalServerError)
		return
	}

	decodedContent, err := decodeSubContent(subContent)
	if err != nil {
		http.Error(w, "base64 decode sub_content error", http.StatusInternalServerError)
		return
	}

	content, err := h.nodeService.ConvertToCFIPSubscription(decodedContent, r.URL.Query().Get("file_type"), h.cfIPService)
	if err != nil {
		http.Error(w, "convert_cf_better_ips_to_vmess error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(content))
}

func decodeSubContent(subContent string) (string, error) {
	trimmed := strings.TrimSpace(subContent)
	if strings.HasPrefix(trimmed, "vmess://") {
		return trimmed, nil
	}

	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(decoded)), nil
}

type convertedFileOptions struct {
	configName  string
	outputName  string
	target      string
	contentType string
	sourceURL   string
	configURL   string
	postProcess func(path string) error
}

func (h *Handler) handleConvertedFile(w http.ResponseWriter, r *http.Request, opts convertedFileOptions) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}

	merged, err := h.getMergedSubscription()
	if err != nil {
		h.writeJSONError(w, http.StatusInternalServerError, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	// Use provided configURL or fall back to default
	configURL := opts.configURL
	if configURL == "" {
		configURL = normalINIURL
	}

	outputPath, err := h.converterService.Convert(ctx, opts.configName, map[string]string{
		"exclude":  "流量|过期时间|地址|故障",
		"target":   opts.target,
		"url":      opts.sourceURL,
		"scv":      "false",
		"new_name": "true",
		"config":   configURL,
	}, opts.outputName)
	if err != nil {
		h.writeJSONError(w, http.StatusInternalServerError, err)
		return
	}

	if opts.postProcess != nil {
		if err := opts.postProcess(outputPath); err != nil {
			h.writeJSONError(w, http.StatusInternalServerError, err)
			return
		}
	}

	content, err := os.ReadFile(outputPath)
	if err != nil {
		h.writeJSONError(w, http.StatusInternalServerError, err)
		return
	}

	zipped, err := gzipData(content)
	if err != nil {
		h.writeJSONError(w, http.StatusInternalServerError, err)
		return
	}

	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Content-Type", opts.contentType)
	w.Header().Set("Subscription-Userinfo", merged.SubscriptionUserinfo)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", opts.outputName))
	_, _ = w.Write(zipped)
}

func (h *Handler) getMergedSubscription() (*model.SubscriptionContent, error) {
	h.cacheMu.Lock()
	defer h.cacheMu.Unlock()

	now := time.Now()
	if h.subscriptionData != nil && now.Before(h.subscriptionData.expiresAt) {
		return h.subscriptionData.value, nil
	}

	subURLs, err := h.subscriptionService.GetSubUrls()
	if err != nil {
		return nil, err
	}
	merged, err := h.subscriptionService.MergeSubContent(subURLs, splitExtendNodes(h.cfg.ExtendSubNodes), h.cfg.ZCSSRSubUseDomain)
	if err != nil {
		return nil, err
	}

	h.subscriptionData = &cachedSubscription{
		value:     merged,
		expiresAt: now.Add(time.Duration(h.cfg.SubCacheTTL) * time.Second),
	}
	return merged, nil
}

func splitExtendNodes(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	items := strings.Split(raw, "\n")
	nodes := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			nodes = append(nodes, item)
		}
	}
	return nodes
}

func gzipData(content []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	if _, err := writer.Write(content); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (h *Handler) writeJSONError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": "An error occurred",
		"msg":   err.Error(),
	})
}

func (h *Handler) absoluteURL(r *http.Request, defaultScheme, path string) string {
	scheme := defaultScheme
	if r.TLS != nil {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s%s", scheme, r.Host, path)
}

func (h *Handler) internalLinksURL() string {
	return fmt.Sprintf("http://127.0.0.1:%d/sub/links.txt", h.cfg.ServerPort)
}

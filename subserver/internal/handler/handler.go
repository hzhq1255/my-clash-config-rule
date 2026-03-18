package handler

import (
	"net/http"

	"github.com/hzhq1255/my-clash-config-rule/subserver/internal/config"
)

// Handler holds dependencies for HTTP handlers
type Handler struct {
	cfg *config.Config
	// TODO: Add service dependencies
}

// New creates a new handler
func New(cfg *config.Config) *Handler {
	return &Handler{
		cfg: cfg,
	}
}

// Routes returns all HTTP routes
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()

	// Subscription endpoints
	mux.HandleFunc("/sub/links.txt", h.handleLinks)
	mux.HandleFunc("/sub/normal.yaml", h.handleNormalYAML)
	mux.HandleFunc("/sub/surfboard.txt", h.handleSurfboard)
	mux.HandleFunc("/sub/convert_cf_better_ips", h.handleConvertCFIPs)

	// Health check
	mux.HandleFunc("/health", h.handleHealth)

	return mux
}

// handleHealth returns health status
func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// handleLinks returns merged subscription links
func (h *Handler) handleLinks(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement subscription merge logic
	w.Header().Set("Content-Type", "application/octet-stream; charset=utf-8")
	w.Write([]byte("TODO: links.txt"))
}

// handleNormalYAML returns Clash configuration
func (h *Handler) handleNormalYAML(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement Clash config generation
	w.Header().Set("Content-Type", "application/octet-stream; charset=utf-8")
	w.Write([]byte("TODO: normal.yaml"))
}

// handleSurfboard returns Surfboard configuration
func (h *Handler) handleSurfboard(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement Surfboard config generation
	w.Header().Set("Content-Type", "application/octet-stream; charset=utf-8")
	w.Write([]byte("TODO: surfboard.txt"))
}

// handleConvertCFIPs converts vmess subscription to CF better IPs
func (h *Handler) handleConvertCFIPs(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement CF IP conversion
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("TODO: convert_cf_better_ips"))
}

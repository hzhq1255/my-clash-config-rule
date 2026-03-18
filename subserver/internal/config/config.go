package config

import (
	"errors"
	"os"
	"strconv"
)

// Config holds all configuration from environment variables
type Config struct {
	// Server
	ServerPort int
	LogLevel   string

	// Subscription service
	ZCSSRUserEmail    string
	ZCSSRUserPasswd   string
	ZCSSRDomain       string
	ZCSSRSubUseDomain bool
	ExtendSubNodes    string

	// GitHub proxy
	GHProxyDomain string

	// Subconverter
	SubconverterVersion     string
	SubconverterDownloadURL string

	// Cache TTL (seconds)
	LoginCacheTTL int
	SubCacheTTL   int
	FileCacheTTL  int
}

// Load reads configuration from environment variables
func Load() (*Config, error) {
	cfg := &Config{}

	// Server config
	port := os.Getenv("SERVER_PORT")
	if port == "" {
		cfg.ServerPort = 8080
	} else {
		p, err := strconv.Atoi(port)
		if err != nil {
			return nil, errors.New("invalid SERVER_PORT")
		}
		cfg.ServerPort = p
	}

	cfg.LogLevel = os.Getenv("LOG_LEVEL")
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}

	// Required subscription service config
	cfg.ZCSSRUserEmail = os.Getenv("ZCSSR_USER_EMAIL")
	if cfg.ZCSSRUserEmail == "" {
		return nil, errors.New("ZCSSR_USER_EMAIL is required")
	}

	cfg.ZCSSRUserPasswd = os.Getenv("ZCSSR_USER_PASSWD")
	if cfg.ZCSSRUserPasswd == "" {
		return nil, errors.New("ZCSSR_USER_PASSWD is required")
	}

	cfg.ZCSSRDomain = os.Getenv("ZCSSR_DOMAIN")
	if cfg.ZCSSRDomain == "" {
		return nil, errors.New("ZCSSR_DOMAIN is required")
	}

	// Optional subscription config
	useDomain := os.Getenv("ZCSSR_SUB_USE_DOMAIN")
	cfg.ZCSSRSubUseDomain = useDomain == "true"

	cfg.ExtendSubNodes = os.Getenv("EXTEND_SUB_NODES")

	// GitHub proxy
	cfg.GHProxyDomain = os.Getenv("GHPROXY_DOMAIN")
	if cfg.GHProxyDomain == "" {
		cfg.GHProxyDomain = "ghp.ci"
	}

	// Subconverter config
	cfg.SubconverterVersion = os.Getenv("SUBCONVERTER_VERSION")
	if cfg.SubconverterVersion == "" {
		cfg.SubconverterVersion = "v0.9.2"
	}
	cfg.SubconverterDownloadURL = os.Getenv("SUBCONVERTER_DOWNLOAD_URL")

	// Cache TTL
	cfg.LoginCacheTTL = 28800 // 8 hours
	cfg.SubCacheTTL = 300     // 5 minutes
	cfg.FileCacheTTL = 86400  // 24 hours

	return cfg, nil
}

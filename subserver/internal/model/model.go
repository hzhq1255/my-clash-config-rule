package model

// LoginResponse represents the login API response
type LoginResponse struct {
	Ret int `json:"ret"`
}

// IpItem represents a single Cloudflare IP item
type IpItem struct {
	Name   string `json:"name"`
	IP     string `json:"ip"`
	Colo   string `json:"colo"`
	Speed  int    `json:"speed"`
	Uptime int    `json:"uptime"`
}

// IpData represents Cloudflare IP data response
type IpData struct {
	Data struct {
		V4 map[string][]IpItem `json:"v4"`
		V6 map[string][]IpItem `json:"v6"`
	} `json:"data"`
}

// VmessNode represents a vmess node configuration
type VmessNode struct {
	V    string `json:"v"`    // version
	Ps   string `json:"ps"`   // ps (name)
	Add  string `json:"add"`  // address
	Port string `json:"port"` // port
	ID   string `json:"id"`   // uuid
	Aid  string `json:"aid"`  // alterId
	Scy  string `json:"scy"`  // cipher
	Net  string `json:"net"`  // network
	Type string `json:"type"` // type
	Host string `json:"host"` // host
	Path string `json:"path"` // path
	TLS  string `json:"tls"`  // tls
	SNI  string `json:"sni"`  // sni
	Alpn string `json:"alpn"` // alpn
	FP   string `json:"fp"`   // fingerprint
}

// ClashProxy represents a Clash proxy configuration
type ClashProxy struct {
	Name           string    `json:"name" yaml:"name"`
	Server         string    `json:"server" yaml:"server"`
	Port           int       `json:"port" yaml:"port"`
	Type           string    `json:"type" yaml:"type"`
	UUID           string    `json:"uuid" yaml:"uuid"`
	AlterID        int       `json:"alterId" yaml:"alterId"`
	Cipher         string    `json:"cipher" yaml:"cipher"`
	TLS            bool      `json:"tls" yaml:"tls"`
	SkipCertVerify bool      `json:"skip-cert-verify" yaml:"skip-cert-verify"`
	ServerName     string    `json:"servername" yaml:"servername"`
	Network        string    `json:"network" yaml:"network"`
	WSOpts         WSOptions `json:"ws-opts" yaml:"ws-opts"`
}

// WSOptions represents WebSocket options
type WSOptions struct {
	Path    string            `json:"path" yaml:"path"`
	Headers map[string]string `json:"headers" yaml:"headers"`
}

// SubscriptionContent represents subscription content with metadata
type SubscriptionContent struct {
	Content              string
	SubscriptionUserinfo string
}

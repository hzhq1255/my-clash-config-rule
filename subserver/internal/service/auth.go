package service

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hzhq1255/my-clash-config-rule/subserver/internal/model"
)

// AuthService handles authentication.
type AuthService struct {
	client       *http.Client
	domain       string
	email        string
	passwd       string
	sessionMutex sync.RWMutex
	loginTime    time.Time
}

// NewAuthService creates a new auth service.
func NewAuthService(domain, email, passwd string) (*AuthService, error) {
	client, err := newHTTPClient()
	if err != nil {
		return nil, err
	}

	return &AuthService{
		client: client,
		domain: domain,
		email:  email,
		passwd: passwd,
	}, nil
}

func newHTTPClient() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create cookie jar: %w", err)
	}

	return &http.Client{
		Timeout: 30 * time.Second,
		Jar:     jar,
	}, nil
}

// Login performs login and stores the authenticated session in the cookie jar.
func (s *AuthService) Login() error {
	s.sessionMutex.Lock()
	defer s.sessionMutex.Unlock()

	if !s.loginTime.IsZero() && time.Since(s.loginTime) < 8*time.Hour {
		return nil
	}

	if err := s.loginOnce(false); err != nil {
		slog.Warn("Primary login attempt failed, retrying with fresh session", "error", err)
		client, newClientErr := newHTTPClient()
		if newClientErr != nil {
			return newClientErr
		}
		s.client = client
		s.loginTime = time.Time{}
		if retryErr := s.loginOnce(true); retryErr != nil {
			return retryErr
		}
	}

	s.loginTime = time.Now()
	slog.Info("Login successful")
	return nil
}

func (s *AuthService) loginOnce(primeSession bool) error {
	loginURL := fmt.Sprintf("https://%s/auth/login", s.domain)
	if primeSession {
		req, err := http.NewRequest(http.MethodGet, loginURL, nil)
		if err != nil {
			return fmt.Errorf("create login page request: %w", err)
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		resp, err := s.client.Do(req)
		if err != nil {
			return fmt.Errorf("prime login page request failed: %w", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	form := url.Values{}
	form.Set("email", s.email)
	form.Set("passwd", s.passwd)
	form.Set("code", "")

	req, err := http.NewRequest(http.MethodPost, loginURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("create login request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Set("Origin", fmt.Sprintf("https://%s", s.domain))
	req.Header.Set("Referer", loginURL)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read login response: %w", err)
	}

	var loginResp model.LoginResponse
	if err := parseLoginResponse(body, &loginResp); err != nil {
		slog.Warn("Unexpected login response", "body_preview", previewBody(body))
		return fmt.Errorf("parse login response: %w", err)
	}
	if loginResp.Ret != 1 {
		return fmt.Errorf("login failed with ret=%d", loginResp.Ret)
	}

	return nil
}

// DoRequest executes a request with an active authenticated session.
func (s *AuthService) DoRequest(req *http.Request) (*http.Response, error) {
	if err := s.Login(); err != nil {
		return nil, err
	}
	return s.client.Do(req)
}

func parseLoginResponse(body []byte, out *model.LoginResponse) error {
	trimmed := strings.TrimSpace(string(body))
	if err := json.Unmarshal([]byte(trimmed), out); err == nil {
		return nil
	}

	start := strings.Index(trimmed, "{")
	end := strings.LastIndex(trimmed, "}")
	if start >= 0 && end > start {
		return json.Unmarshal([]byte(trimmed[start:end+1]), out)
	}

	return fmt.Errorf("non-json login response")
}

func previewBody(body []byte) string {
	trimmed := strings.TrimSpace(string(body))
	if len(trimmed) > 240 {
		return trimmed[:240]
	}
	return trimmed
}
